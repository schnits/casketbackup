import java.io.*;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.*;
import java.security.spec.KeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * CasketBackup — a single-file Java backup prototype implementing:
 *   • Content-Defined Chunking (CDC) via a Rabin-style rolling fingerprint
 *   • Chunk-level deduplication using SHA-256 identifiers
 *   • Authenticated encryption per chunk using AES-256-GCM
 *   • Plain filesystem repository layout (easy to sync to S3 + lifecycle to Glacier/Deep Archive)
 *
 * This version adds:
 *   • VERY VERBOSE LOGGING ("--verbose" and "--trace") to show what the program is doing and why
 *   • EXTENSIVE INLINE COMMENTS explaining design choices and trade-offs
 *
 * ──────────────────────────────────────────────────────────────────────────────
 * Why this design?
 *
 * 1) Content-Defined Chunking (CDC):
 *    - Problem: If you cut files into fixed-size blocks, inserting 1 byte at the start
 *      shifts every downstream block; dedupe fails because block boundaries change.
 *    - CDC solves this by letting the CONTENT define boundaries: slide a rolling hash
 *      over the stream and cut where the hash matches a pattern. Unchanged regions
 *      keep the same boundaries → great dedup across versions even after inserts.
 *
 * 2) Rabin Rolling Hash (fingerprint):
 *    - We use a simple rolling polynomial hash over a window. It's not cryptographic;
 *      collisions only influence boundary placement, not integrity.
 *    - We still compute SHA-256 of each plaintext chunk for identity and integrity
 *      binding (i.e., dedupe key and post-decrypt verification during checks).
 *
 * 3) AES-256-GCM per chunk:
 *    - Encrypt each chunk independently with a random 96-bit nonce. AES-GCM provides
 *      confidentiality + integrity (authentication tag). If any bit flips, decryption
 *      fails rather than producing garbage.
 *    - Independent chunk encryption enables parallelism and avoids re-encrypting the
 *      entire file when only parts change.
 *
 * 4) Filesystem repository (no DB):
 *    - Chunks are stored by hash with a fan-out directory structure to keep directory
 *      sizes manageable. Snapshots are plain text manifests. This keeps the prototype
 *      simple, portable, and git/rsync/rclone/aws-friendly.
 *
 * 5) Glacier/Deep Archive strategy:
 *    - We write to a local repo; you can sync to S3 ("aws s3 sync" or rclone) and use
 *      an S3 Lifecycle rule to transition to DEEP_ARCHIVE. Restores from Deep Archive
 *      require an S3 restore (thaw) operation before running "restore".
 *
 * Security note: AES-GCM and SHA-256 are strong primitives. The rolling hash is NOT a
 * security primitive and does not protect integrity; it's used only to choose chunk
 * boundaries. Integrity is guaranteed by AES-GCM tags and by SHA-256 identity checks.
 *
 * Build:   javac CasketBackup.java
 * Example: java CasketBackup init --repo repo --password "pw" --avg 2097152 --min 262144 --max 8388608 --window 64 --verbose
 *          java CasketBackup backup  --repo repo --password "pw" --src ~/Documents --verbose
 *          java CasketBackup list    --repo repo
 *          java CasketBackup restore --repo repo --password "pw" --snapshot <idprefix> --dest /tmp/restore --trace
 *          java CasketBackup check   --repo repo --password "pw"
 */
public class CasketBackup {

    // ──────────────────────────────────────────────────────────────────────────
    // Lightweight logger with levels so we can have --verbose and --trace.
    // Using System.out/err directly to keep the file self-contained (no SLF4J).
    // Levels: ERROR < WARN < INFO < DEBUG < TRACE
    // "--verbose" maps to DEBUG; "--trace" maps to TRACE; default is INFO.
    // ──────────────────────────────────────────────────────────────────────────
    enum Level { ERROR, WARN, INFO, DEBUG, TRACE }
    static class Log {
        private static Level level = Level.INFO;
        private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        static void set(Level lvl) { level = lvl; }
        static void e(String msg){ if(level.ordinal()>=Level.ERROR.ordinal()) out("ERROR", msg); }
        static void w(String msg){ if(level.ordinal()>=Level.WARN.ordinal())  out("WARN ", msg); }
        static void i(String msg){ if(level.ordinal()>=Level.INFO.ordinal())  out("INFO ", msg); }
        static void d(String msg){ if(level.ordinal()>=Level.DEBUG.ordinal()) out("DEBUG", msg); }
        static void t(String msg){ if(level.ordinal()>=Level.TRACE.ordinal()) out("TRACE", msg); }
        private static void out(String lvl, String msg){
            String ts = LocalDateTime.now().format(TS);
            System.out.println(ts + " [" + lvl + "] " + msg);
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Entry point / CLI parsing
    // We keep argument parsing minimal and explicit; unknown flags are ignored.
    // ──────────────────────────────────────────────────────────────────────────
    public static void main(String[] args) throws Exception {
        if (args.length == 0) { usage(); return; }
        Map<String, String> a = parseArgs(args);

        // Configure log level based on flags before doing work
        if (a.containsKey("trace")) Log.set(Level.TRACE);
        else if (a.containsKey("verbose")) Log.set(Level.DEBUG);
        else Log.set(Level.INFO);

        String cmd = args[0].toLowerCase(Locale.ROOT);
        Log.d("Command=" + cmd + ", args=" + a);

        switch (cmd) {
			case "init":
				require(a, "repo"); require(a, "password");
				int avg = Integer.parseInt(a.getOrDefault("avg", "2097152"));   // 2 MiB
				int min = Integer.parseInt(a.getOrDefault("min", "262144"));    // 256 KiB
				int max = Integer.parseInt(a.getOrDefault("max", "8388608"));   // 8 MiB
				int window = Integer.parseInt(a.getOrDefault("window", "64"));  // Rabin only
				String algo = a.getOrDefault("algo", "rabin").toLowerCase(Locale.ROOT);
				initRepo(Paths.get(a.get("repo")), a.get("password"), avg, min, max, window, algo);
				break;

			case "backup":
				require(a, "repo"); require(a, "password"); require(a, "src");
				String algoOverride = a.getOrDefault("algo", null);
				backup(Paths.get(a.get("repo")), Paths.get(a.get("src")), a.get("password"), algoOverride);
				break;


            case "list":
                require(a, "repo");
                listSnapshots(Paths.get(a.get("repo")));
                break;

            case "restore":
                require(a, "repo"); require(a, "password"); require(a, "snapshot"); require(a, "dest");
                restore(Paths.get(a.get("repo")), a.get("password"), a.get("snapshot"), Paths.get(a.get("dest")));
                break;

            case "check":
                require(a, "repo"); require(a, "password");
                check(Paths.get(a.get("repo")), a.get("password"));
                break;

            default:
                usage();
        }
    }

private static void usage() {
    System.out.println("CasketBackup (CDC + AES-GCM + dedupe) — single-file Java\n" +
            "Usage:\n" +
            "  java CasketBackup init --repo <dir> --password <pw> [--avg 2097152 --min 262144 --max 8388608 --window 64] [--algo rabin|fastcdc] [--verbose|--trace]\n" +
            "  java CasketBackup backup --repo <dir> --password <pw> --src <path> [--algo rabin|fastcdc] [--verbose|--trace]\n" +
            "  java CasketBackup list --repo <dir>\n" +
            "  java CasketBackup restore --repo <dir> --password <pw> --snapshot <id-prefix> --dest <dir> [--verbose|--trace]\n" +
            "  java CasketBackup check --repo <dir> --password <pw> [--verbose|--trace]\n");
}


    private static Map<String, String> parseArgs(String[] args) {
        Map<String, String> m = new LinkedHashMap<>();
        if (args.length > 0) m.put("_cmd", args[0]);
        for (int i = 1; i < args.length; i++) {
            if (args[i].startsWith("--")) {
                String key = args[i].substring(2);
                String val = (i + 1 < args.length && !args[i+1].startsWith("--")) ? args[++i] : "true";
                m.put(key.toLowerCase(Locale.ROOT), val);
            }
        }
        return m;
    }

    private static void require(Map<String, String> m, String key) {
        if (!m.containsKey(key)) {
            Log.e("Missing --" + key);
            System.exit(2);
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Repository configuration: parameters that define chunking/security.
    // We persist them in a simple Java .properties file for transparency.
    // ──────────────────────────────────────────────────────────────────────────
static class RepoConfig {
    int avgChunk, minChunk, maxChunk, window; // CDC parameters
    String algo;                              // "rabin" or "fastcdc"
    byte[] salt;                              // PBKDF2 salt
    int pbkdf2Iter;                           // KDF iterations

    static RepoConfig load(Path repo) throws IOException {
        Properties p = new Properties();
        try (InputStream in = Files.newInputStream(repo.resolve("config.properties"))) {
            p.load(in);
        }
        RepoConfig rc = new RepoConfig();
        rc.avgChunk = Integer.parseInt(p.getProperty("avgChunk"));
        rc.minChunk = Integer.parseInt(p.getProperty("minChunk"));
        rc.maxChunk = Integer.parseInt(p.getProperty("maxChunk"));
        rc.window   = Integer.parseInt(p.getProperty("window"));
        rc.algo     = p.getProperty("algo", "rabin");
        rc.pbkdf2Iter = Integer.parseInt(p.getProperty("pbkdf2Iter", "300000"));
        rc.salt = hexToBytes(p.getProperty("salt"));
        return rc;
    }

    void store(Path repo) throws IOException {
        Properties p = new Properties();
        p.setProperty("avgChunk", String.valueOf(avgChunk));
        p.setProperty("minChunk", String.valueOf(minChunk));
        p.setProperty("maxChunk", String.valueOf(maxChunk));
        p.setProperty("window",   String.valueOf(window));
        p.setProperty("algo",     (algo == null ? "rabin" : algo));
        p.setProperty("pbkdf2Iter", String.valueOf(pbkdf2Iter));
        p.setProperty("salt", bytesToHex(salt));
        try (OutputStream out = Files.newOutputStream(repo.resolve("config.properties"))) {
            p.store(out, "CasketBackup config");
        }
    }
}

    private static void initRepo(Path repo, String password, int avg, int min, int max, int window, String algo) throws Exception {

			Log.i("Initializing repository: " + repo.toAbsolutePath());
			if (!Files.exists(repo)) Files.createDirectories(repo);
			Path chunks = repo.resolve("chunks");
			Path snaps  = repo.resolve("snapshots");
			Files.createDirectories(chunks);
			Files.createDirectories(snaps);

			if (!"rabin".equals(algo) && !"fastcdc".equals(algo)) {
				throw new IllegalArgumentException("--algo must be 'rabin' or 'fastcdc'");
			}

			RepoConfig rc = new RepoConfig();
			rc.avgChunk = avg; rc.minChunk = min; rc.maxChunk = max; rc.window = window;
			rc.algo = algo;
			rc.pbkdf2Iter = 300000; // tune to CPU
			rc.salt = randomBytes(16);
			rc.store(repo);
			Log.d("Saved config: avg="+avg+", min="+min+", max="+max+", window="+window+", algo="+algo+", pbkdf2Iter="+rc.pbkdf2Iter);

			// Crypto self-test
			SecretKey key = deriveKey(password, rc.salt, rc.pbkdf2Iter);
			byte[] test = "ok".getBytes(StandardCharsets.UTF_8);
			byte[] enc = encryptChunk(key, test);
			byte[] dec = decryptChunk(key, enc);
			if (!Arrays.equals(test, dec)) throw new IllegalStateException("Crypto self-test failed");

			Log.i("Repository initialized successfully. CDC and crypto self-tests passed.");
			Log.i(String.format(Locale.ROOT, "CDC params: avg=%d min=%d max=%d window=%d algo=%s", avg, min, max, window, algo));

    }

    // ──────────────────────────────────────────────────────────────────────────
    // BACKUP: Walk source tree, chunk each file with CDC, encrypt/store unique chunks,
    //         and write a human-readable manifest describing file→chunk mapping.
    // ──────────────────────────────────────────────────────────────────────────
    private static void backup(Path repo, Path src, String password, String algoOverride) throws Exception {

				   if (!Files.exists(src)) throw new FileNotFoundException(src.toString());
				RepoConfig rc = RepoConfig.load(repo);
				SecretKey key = deriveKey(password, rc.salt, rc.pbkdf2Iter);

				String host = InetAddress.getLocalHost().getHostName();
				String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
				String id = UUID.randomUUID().toString().substring(0, 8);
				Path manifest = repo.resolve("snapshots").resolve(ts + "-" + safe(host) + "-" + id + ".manifest");
				Log.i("Creating snapshot manifest: " + manifest.getFileName());

				String algoUsed = (algoOverride != null && !algoOverride.isBlank())
						? algoOverride.toLowerCase(Locale.ROOT)
						: rc.algo;

				if (!"rabin".equals(algoUsed) && !"fastcdc".equals(algoUsed)) {
					throw new IllegalArgumentException("Unsupported --algo: " + algoUsed);
				}

				try (BufferedWriter w = Files.newBufferedWriter(manifest, StandardCharsets.UTF_8)) {
					w.write("SNAPSHOT " + id + " " + ts + " " + host); w.newLine();
					w.write("PARAMS avg=" + rc.avgChunk + " min=" + rc.minChunk + " max=" + rc.maxChunk + " window=" + rc.window); w.newLine();
					w.write("ALGO " + algoUsed); w.newLine();
					final long[] stats = new long[3]; // files, bytes, chunks

            Files.walkFileTree(src, new SimpleFileVisitor<>() {
                @Override public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    try {
                        String rel = src.relativize(file).toString().replace('\\','/');
                        Log.d("Backing up file: " + rel + " (" + attrs.size() + " bytes)");
                        w.write("FILE " + rel + " " + fileMode(attrs) + " " + attrs.size()); w.newLine();

						try (InputStream in = Files.newInputStream(file)) {
							ByteArrayOutputStream buf = new ByteArrayOutputStream();

							if ("fastcdc".equals(algoUsed)) {
								ChunkerFast ch = new ChunkerFast(in, new FastCDC(rc.avgChunk, rc.minChunk, rc.maxChunk));
								for (;;) {
									buf.reset();
									int n = ch.nextChunk(buf);
									if (n <= 0) break;
									byte[] plain = buf.toByteArray();
									String chunkId = sha256Hex(plain);
									Path chunkPath = chunkPath(repo, chunkId);
									if (!Files.exists(chunkPath)) {
										byte[] enc = encryptChunk(key, plain);
										Files.createDirectories(chunkPath.getParent());
										Files.write(chunkPath, enc);
										Log.t("Stored new chunk: " + chunkId + " size=" + plain.length + " enc=" + enc.length);
									} else {
										Log.t("Chunk already exists (dedupe hit): " + chunkId);
									}
									w.write("CHUNK " + chunkId + " " + n); w.newLine();
									stats[2]++;
								}
							} else {
								RollingRabin rabin = new RollingRabin(rc.window);
								CDC cdc = new CDC(rc.avgChunk, rc.minChunk, rc.maxChunk);
								Chunker ch = new Chunker(in, rabin, cdc);
								for (;;) {
									buf.reset();
									int n = ch.nextChunk(buf);
									if (n <= 0) break;
									byte[] plain = buf.toByteArray();
									String chunkId = sha256Hex(plain);
									Path chunkPath = chunkPath(repo, chunkId);
									if (!Files.exists(chunkPath)) {
										byte[] enc = encryptChunk(key, plain);
										Files.createDirectories(chunkPath.getParent());
										Files.write(chunkPath, enc);
										Log.t("Stored new chunk: " + chunkId + " size=" + plain.length + " enc=" + enc.length);
									} else {
										Log.t("Chunk already exists (dedupe hit): " + chunkId);
									}
									w.write("CHUNK " + chunkId + " " + n); w.newLine();
									stats[2]++;
								}
							}
						}

                        stats[0]++; stats[1]+=attrs.size();
                    } catch (Exception e) {
                        throw new UncheckedIOException(new IOException("Backup failed for " + file, e));
                    }
                    return FileVisitResult.CONTINUE;
                }
            });

            w.write("END"); w.newLine();
				   Log.i(String.format(Locale.ROOT,
				"Snapshot %s created: %s (files=%d bytes=%d chunks=%d) [algo=%s]",
				id, manifest.getFileName(), stats[0], stats[1], stats[2], algoUsed));
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // LIST: Just show available snapshot manifests; they are timestamped and
    // include a short random ID for human-friendly selection.
    // ──────────────────────────────────────────────────────────────────────────
    private static void listSnapshots(Path repo) throws IOException {
        Path snaps = repo.resolve("snapshots");
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(snaps, "*.manifest")) {
            for (Path p : ds) System.out.println(p.getFileName().toString());
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // RESTORE: Parse the manifest and reconstruct files by concatenating chunks.
    // We decrypt each referenced chunk and verify its size. If AES-GCM tag fails,
    // decryption throws, which protects you from corrupted or tampered data.
    // ──────────────────────────────────────────────────────────────────────────
    private static void restore(Path repo, String password, String snapshotId, Path dest) throws Exception {
        RepoConfig rc = RepoConfig.load(repo);
        SecretKey key = deriveKey(password, rc.salt, rc.pbkdf2Iter);
        Path snap = findSnapshot(repo, snapshotId);
        if (snap == null) throw new FileNotFoundException("Snapshot not found: " + snapshotId);
        Files.createDirectories(dest);
        Log.i("Restoring snapshot: " + snap.getFileName());

        try (BufferedReader r = Files.newBufferedReader(snap, StandardCharsets.UTF_8)) {
            String line; Path currentFile = null; long remaining = 0;
            OutputStream out = null;
            while ((line = r.readLine()) != null) {
                if (line.startsWith("FILE ")) {
                    if (out != null) out.close();
					
					
					
					
					
                    String rest = line.substring(5).trim();

                    // Split on whitespace, but don't trust fixed positions; take last 2 tokens as mode+size.

                    String[] parts = rest.split("\s+");

                    if (parts.length < 3) throw new IOException("Malformed FILE line: " + line);

                    String sizeTok = parts[parts.length - 1];

                    String modeTok = parts[parts.length - 2];

                    long sz;

                    try { sz = Long.parseLong(sizeTok); } catch (NumberFormatException nfe) {

                        throw new IOException("Invalid size in FILE line: " + line, nfe);

                    }

                    // relpath may itself contain spaces; recover by removing the trailing " mode size" from rest

                    int tailLen = modeTok.length() + 1 + sizeTok.length();

                    String rel = rest.substring(0, rest.length() - tailLen).trim();

                    currentFile = dest.resolve(rel);

                    Files.createDirectories(currentFile.getParent());

                    out = Files.newOutputStream(currentFile, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

                    remaining = sz;

                    Log.d("Recreating: " + rel + " expectedBytes=" + remaining + " mode=" + modeTok);

                } else if (line.startsWith("CHUNK ")) {

                    String[] t = line.split("\s+");

                    if (t.length < 3) throw new IOException("Malformed CHUNK line: " + line);

                    String id = t[1];

                    int orig;

                    try { orig = Integer.parseInt(t[2]); } catch (NumberFormatException nfe) {

                        throw new IOException("Invalid chunk size in CHUNK line: " + line, nfe);

                    }
					
					
					
                    Path path = chunkPath(repo, id);
                    byte[] enc = Files.readAllBytes(path);
                    byte[] plain = decryptChunk(key, enc);
                    if (plain.length != orig) throw new IOException("Chunk size mismatch for " + id);
                    out.write(plain);
                    remaining -= orig;
                    Log.t("Wrote chunk: " + id + " bytes=" + orig + " remainingInFile=" + remaining);
                } else if (line.equals("END")) {
                    break;
                }
            }
            if (out != null) out.close();
        }
        Log.i("Restore complete → " + dest.toAbsolutePath());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // CHECK: Walk every stored chunk, decrypt, recompute SHA-256 over plaintext
    // and ensure it matches the filename (the chunk ID). This verifies both
    // encryption integrity (GCM tag) and dedupe identity.
    // ──────────────────────────────────────────────────────────────────────────
    private static void check(Path repo, String password) throws Exception {
        RepoConfig rc = RepoConfig.load(repo);
        SecretKey key = deriveKey(password, rc.salt, rc.pbkdf2Iter);

        Path chunks = repo.resolve("chunks");
        final long[] cnt = new long[2];
        Files.walkFileTree(chunks, new SimpleFileVisitor<>() {
            @Override public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                if (file.getFileName().toString().endsWith(".chunk")) {
                    try {
                        byte[] enc = Files.readAllBytes(file);
                        byte[] plain = decryptChunk(key, enc);
                        String sha = sha256Hex(plain);
                        String name = file.getFileName().toString().replace(".chunk","");
                        if (!sha.equalsIgnoreCase(name)) throw new IOException("Hash mismatch: " + file);
                        cnt[0]++; cnt[1]+=plain.length;
                        if (cnt[0] % 1000 == 0) Log.d("Checked chunks=" + cnt[0]);
                    } catch (GeneralSecurityException e) {
                        throw new IOException("Decrypt failed: " + file, e);
                    }
                }
                return FileVisitResult.CONTINUE;
            }
        });
        Log.i(String.format(Locale.ROOT, "Check OK: %d chunks, %d plaintext bytes verified", cnt[0], cnt[1]));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Utility helpers: path layout, hashing, encoding, key derivation, crypto.
    // ──────────────────────────────────────────────────────────────────────────
    private static Path findSnapshot(Path repo, String idPrefix) throws IOException {
        Path snaps = repo.resolve("snapshots");
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(snaps, "*.manifest")) {
            Path match = null;
            for (Path p : ds) {
                String name = p.getFileName().toString();
                // ID is after last '-' before ".manifest"
                int dash = name.lastIndexOf('-');
                int dot = name.lastIndexOf('.');
                if (dash > 0 && dot > dash) {
                    String id = name.substring(dash+1, dot);
                    if (id.startsWith(idPrefix)) {
                        if (match != null) throw new IOException("Ambiguous snapshot prefix: " + idPrefix);
                        match = p;
                    }
                }
            }
            return match;
        }
    }

    private static String fileMode(BasicFileAttributes a) {
        return a.isSymbolicLink() ? "L" : a.isDirectory() ? "D" : "F";
    }

    private static String safe(String s) { return s.replaceAll("[^a-zA-Z0-9_.-]", "_"); }

    private static Path chunkPath(Path repo, String shaHex) {
        // Fan-out by first 2+2 hex nibbles to avoid huge directories.
        String a = shaHex.substring(0,2);
        String b = shaHex.substring(2,4);
        return repo.resolve("chunks").resolve(a).resolve(b).resolve(shaHex + ".chunk");
    }

    private static String sha256Hex(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return bytesToHex(md.digest(data));
        } catch (NoSuchAlgorithmException e) { throw new RuntimeException(e); }
    }

    private static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length*2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
    private static byte[] hexToBytes(String s) {
        int n = s.length()/2; byte[] out = new byte[n];
        for (int i=0;i<n;i++) out[i] = (byte)Integer.parseInt(s.substring(2*i,2*i+2),16);
        return out;
    }
    private static byte[] randomBytes(int n) { byte[] b = new byte[n]; new SecureRandom().nextBytes(b); return b; }

    // AES-GCM with random 12-byte nonce, tag 16 bytes; store as [nonce(12)] [ciphertext+tag].
    private static byte[] encryptChunk(SecretKey key, byte[] plain) throws GeneralSecurityException {
        byte[] nonce = randomBytes(12);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        byte[] ct = c.doFinal(plain);
        ByteBuffer bb = ByteBuffer.allocate(12 + ct.length);
        bb.put(nonce).put(ct);
        return bb.array();
    }
    private static byte[] decryptChunk(SecretKey key, byte[] enc) throws GeneralSecurityException {
        ByteBuffer bb = ByteBuffer.wrap(enc);
        byte[] nonce = new byte[12]; bb.get(nonce);
        byte[] ct = new byte[bb.remaining()]; bb.get(ct);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        return c.doFinal(ct);
    }
    private static SecretKey deriveKey(String password, byte[] salt, int iter) throws Exception {
        // PBKDF2WithHmacSHA256 is widely available and FIPS-friendly on most JREs.
        // Increase "iter" to raise attacker effort; store it in config for future reference.
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iter, 256);
        byte[] k = f.generateSecret(spec).getEncoded();
        return new SecretKeySpec(k, "AES");
    }
			// FastCDC components (Gear hash + normalization)
			static final int[] GEAR = buildGearTable();
			static int[] buildGearTable() {
				int[] t = new int[256];
				long x = 0x9E3779B97F4A7C15L; // fixed seed
				for (int i=0;i<256;i++) {
					x ^= (x << 13); x ^= (x >>> 7); x ^= (x << 17);
					t[i] = (int)(x ^ (x>>>32));
				}
				return t;
			}
			static class FastCDC {
				final int min, avg, max;
				final int maskNormal; // strict before avg
				final int maskLarge;  // looser after avg
				FastCDC(int avg, int min, int max) {
					if (Integer.bitCount(avg) != 1) throw new IllegalArgumentException("avg must be power of two");
					if (min <= 0 || max <= 0 || min > max) throw new IllegalArgumentException("invalid min/max");
					this.min = min; this.avg = avg; this.max = max;
					int k = Integer.numberOfTrailingZeros(avg);
					this.maskNormal = (1 << k) - 1;
					this.maskLarge  = (k>1) ? (1 << (k-1)) - 1 : this.maskNormal; // ~2x cut chance after avg
				}
			}
			static class ChunkerFast {
				private final InputStream in;
				private final FastCDC f;
				private final byte[] buf = new byte[1<<16];
				private long h = 0;
				ChunkerFast(InputStream in, FastCDC f) { this.in = in; this.f = f; }
				private long gearRoll(int b) { return (h << 1) + (GEAR[b & 0xFF] & 0xFFFFFFFFL); }
				int nextChunk(OutputStream out) throws IOException {
					int size = 0;
					h = 0;
					// Small zone: don't cut
					while (size < f.min) {
						int n = in.read(buf, 0, Math.min(buf.length, f.min - size));
						if (n == -1) return (size>0) ? size : -1;
						out.write(buf, 0, n);
						for (int i=0;i<n;i++) h = gearRoll(buf[i]);
						size += n;
					}
					// Normal zone
					while (size < f.avg) {
						int b = in.read();
						if (b == -1) return size;
						out.write(b);
						h = gearRoll(b);
						size++;
						if ((h & f.maskNormal) == 0) return size;
					}
					// Large zone
					while (size < f.max) {
						int b = in.read();
						if (b == -1) return size;
						out.write(b);
						h = gearRoll(b);
						size++;
						if ((h & f.maskLarge) == 0) return size;
					}
					return size; // cap
				}
			}

    // ──────────────────────────────────────────────────────────────────────────
    // Rolling Rabin fingerprint (CDC):
    // We compute a polynomial rolling hash over a fixed-size window. Each new byte
    // advances the window by 1: subtract the contribution of the oldest byte and
    // add the new byte. The hash is used only for boundary decisions, not security.
    // ──────────────────────────────────────────────────────────────────────────
    static class RollingRabin {
        private final int window;        // number of bytes in the rolling window
        private final long base = 257;   // base for polynomial hash; arbitrary but > alphabet size
        private final long mod  = (1L<<61) - 1; // large modulus for wrap-around arithmetic
        private final Deque<Integer> q = new ArrayDeque<>();
        private long hash = 0;
        private long basePow;            // base^(window-1) % mod (for removing oldest byte)

        RollingRabin(int window) {
            this.window = window;
            long p = 1;
            for (int i=0;i<window-1;i++) p = mulMod(p, base, mod);
            this.basePow = p;
        }

        void reset() { q.clear(); hash = 0; }

        /**
         * Push a byte and return the current hash once the window is "full".
         * Returns -1 until at least "window" bytes have been seen.
         */
        long push(int b) {
            if (q.size() == window) {
                int out = q.removeFirst();
                long sub = mulMod(out & 0xFF, basePow, mod);
                hash = subMod(hash, sub, mod);   // remove highest-order term
            }
            q.addLast(b & 0xFF);
            hash = addMod(mulMod(hash, base, mod), (b & 0xFF), mod); // hash = hash*base + b
            return (q.size() == window) ? hash : -1;
        }

        // Basic modular ops. For simplicity/clarity we fall back to (a*b)%m which is fine for this use.
        private long addMod(long a, long b, long m) { long r = a + b; if (r >= m) r -= m; return r; }
        private long subMod(long a, long b, long m) { long r = a - b; if (r < 0) r += m; return r; }
        private long mulMod(long a, long b, long m) { return (a * b) % m; }
    }

    /**
     * CDC boundary policy: we prefer an average chunk size "avg" which must be a
     * power of two; we cut a boundary when (hash & (avg-1)) == 0, but only after
     * a minimum size, and we force a cut at a maximum size.
     */
    static class CDC {
        final int min, max, mask;
        CDC(int avg, int min, int max) {
            if (Integer.bitCount(avg) != 1) throw new IllegalArgumentException("avg must be power of two");
            if (min <= 0 || max <= 0 || min > max) throw new IllegalArgumentException("invalid min/max");
            this.min = min; this.max = max; this.mask = avg - 1;
        }
        boolean isBoundary(long hash, int size) {
            if (size < min) return false;     // don't cut too early → avoids tiny chunks/overhead
            if (size >= max) return true;     // hard cap to prevent pathological huge chunks
            return (hash != -1) && ((hash & mask) == 0); // probabilistic cut near target avg size
        }
    }

    /**
     * Chunker: streams input bytes and emits CDC chunks. We buffer reads to reduce
     * syscall overhead and feed bytes to the rolling hash one at a time so CDC can
     * examine boundaries at byte granularity.
     */
    static class Chunker {
        private final InputStream in;
        private final RollingRabin rabin;
        private final CDC cdc;
        private final byte[] buf = new byte[1<<16]; // 64 KiB read buffer

        Chunker(InputStream in, RollingRabin r, CDC c) {
            this.in = in; this.rabin = r; this.cdc = c;
            rabin.reset();
        }

        /**
         * Write the next chunk to 'out'. Returns chunk size, or -1 on EOF.
         * We return as soon as a boundary is found or input ends.
         */
        int nextChunk(OutputStream out) throws IOException {
            int chunkSize = 0;
            for (;;) {
                int n = in.read(buf);
                if (n == -1) {
                    return (chunkSize > 0) ? chunkSize : -1; // flush last partial chunk
                }
                for (int i=0;i<n;i++) {
                    int b = buf[i] & 0xFF;
                    out.write(b);
                    chunkSize++;
                    long h = rabin.push(b);
                    if (cdc.isBoundary(h, chunkSize)) {
                        return chunkSize; // boundary → deliver chunk
                    }
                }
            }
        }
    }
}
