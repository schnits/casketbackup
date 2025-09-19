import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * ColdStore — incremental backup with streaming FastCDC + cross-drive dedupe +
 * Reed–Solomon parity. Now includes cross-file parity packer (covers nearly all
 * chunks on a drive), optional per-file parity (auto-disabled when cross-file
 * is enabled), AES-256-GCM encryption (chunks/parity), optional encrypted
 * manifests, location-aware global index, and offline restore planning.
 *
 * Java 11+ (uses InputStream.transferTo). No external libraries.
 */
public class ColdStore {

    // ================= Logger =================

    enum Lvl { OFF, INFO, DEBUG, TRACE }
    static final class LOG {
        static volatile Lvl LEVEL = Lvl.INFO;
        static void set(String s){ try { LEVEL = Lvl.valueOf(s.toUpperCase(Locale.ROOT)); } catch (Exception e) { LEVEL = Lvl.INFO; } }
        static void info (String fmt, Object... a){ if (LEVEL.ordinal()>=Lvl.INFO.ordinal())  out("INFO ", fmt, a); }
        static void debug(String fmt, Object... a){ if (LEVEL.ordinal()>=Lvl.DEBUG.ordinal()) out("DEBUG", fmt, a); }
        static void trace(String fmt, Object... a){ if (LEVEL.ordinal()>=Lvl.TRACE.ordinal()) out("TRACE", fmt, a); }
        private static void out(String lvl, String fmt, Object... a){
            String ts = DateTimeFormatter.ISO_LOCAL_DATE_TIME.format(LocalDateTime.now());
            System.out.printf("%s [%s] %s%n", ts, lvl, String.format(Locale.ROOT, fmt, a));
        }
    }
    static String hb(long n){ String[] u={"B","KiB","MiB","GiB","TiB","PiB"}; double v=n; int i=0; while(v>=1024 && i<u.length-1){ v/=1024; i++; } return String.format(Locale.ROOT,"%.2f %s", v, u[i]); }

    // ================= Main / CLI =================

    public static void main(String[] args) throws Exception {
        Map<String,String> a = parseArgs(args);
        String cmd = a.getOrDefault("_cmd", "");
        LOG.set(a.getOrDefault("--log", "info"));
        if (cmd.isEmpty()) { usage(); return; }

        switch (cmd) {
            case "init" -> {
                Path repo = mustPath(a, "--repo");
                boolean encrypt = Boolean.parseBoolean(a.getOrDefault("--encrypt","false"));
                boolean obfParity = Boolean.parseBoolean(a.getOrDefault("--obfuscate-parity", encrypt ? "true" : "false"));
                boolean encManifest = Boolean.parseBoolean(a.getOrDefault("--encrypt-manifest","false"));

                RepoVolume v = RepoVolume.openOrInit(
                        repo,
                        a.getOrDefault("--name", repo.getFileName().toString()),
                        pInt(a.getOrDefault("--rs-k","8")),
                        pInt(a.getOrDefault("--rs-r","2")),
                        pInt(a.getOrDefault("--min-chunk","262144")),
                        pInt(a.getOrDefault("--avg-chunk","1048576")),
                        pInt(a.getOrDefault("--max-chunk","4194304")),
                        Boolean.parseBoolean(a.getOrDefault("--compress","false")),
                        encrypt, obfParity, encManifest
                );

                Crypto.Ctx crypto = Crypto.ctxForRepo(v, passFrom(a));
                LOG.info("Initialized repo: %s (repo.id=%s drive.id=%s) at %s", v.props.repoName, v.props.repoId, v.props.driveId, repo);
                v.showInfo();
            }
            case "info" -> {
                Path repo = mustPath(a, "--repo");
                RepoVolume v = RepoVolume.openOrInit(repo, null,8,2,262144,1048576,4194304,false,false,false,false);
                v.showInfo();
            }
            case "list" -> {
                Path repo = mustPath(a, "--repo");
                RepoVolume v = RepoVolume.openOrInit(repo, null,8,2,262144,1048576,4194304,false,false,false,false);
                v.listSnapshots();
            }
            case "backup" -> {
                Path repo = mustPath(a, "--repo");
                Path source = mustPath(a, "--source");
                long targetBytes = a.containsKey("--target-bytes") ? pLong(a.get("--target-bytes")) : Long.MAX_VALUE;
                double targetFill = a.containsKey("--target-fill") ? pDouble(a.get("--target-fill")) : -1.0;

                boolean xfileParity = Boolean.parseBoolean(a.getOrDefault("--xfile-parity","false"));
                boolean xfileFinalize = Boolean.parseBoolean(a.getOrDefault("--xfile-finalize-partial","true"));

                RepoVolume v = RepoVolume.openOrInit(repo, null,8,2,262144,1048576,4194304,false,false,false,false);
                Crypto.Ctx crypto = Crypto.ctxForRepo(v, passFrom(a));

                GlobalIndex gidx = null;
                if (a.containsKey("--global-index")) {
                    gidx = GlobalIndex.open(Paths.get(a.get("--global-index")), v.props.repoId, v.props.repoName, v.props.driveId, v.root.toString());
                    LOG.info("Using global index at %s (repoId=%s, driveOrdinal=%d)", Paths.get(a.get("--global-index")).toAbsolutePath(), v.props.repoId, gidx.currentDriveOrdinal());
                }

                String snapName = "SNAP_" + DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH-mm-ss'Z'")
                        .withZone(ZoneOffset.UTC).format(Instant.now());

                LOG.info("Starting backup: snapshot=%s, source=%s, RS(k=%d,r=%d), CDC(min=%s,avg=%s,max=%s), compress=%s, encrypt=%s, encManifest=%s, xfileParity=%s, finalizePartial=%s",
                        snapName, source, v.props.rsK, v.props.rsR,
                        hb(v.props.cMin), hb(v.props.cAvg), hb(v.props.cMax), v.props.compress, v.props.encrypt, v.props.encryptManifest,
                        xfileParity, xfileFinalize);

                Backup.runBackup(v, source, snapName, targetBytes, targetFill, gidx, crypto, xfileParity, xfileFinalize);
            }
            case "restore" -> {
                Path firstRepo = mustPath(a, "--repo");
                String snapshot = a.get("--snapshot");
                boolean unionLatest = Boolean.parseBoolean(a.getOrDefault("--union-latest","false"));
                Path dest = mustPath(a, "--dest");
                String onlyFile = a.get("--only-file");
                String onlyPrefix = a.get("--only-prefix");

                RepoVolume first = RepoVolume.openOrInit(firstRepo, null,8,2,262144,1048576,4194304,false,false,false,false);
                Crypto.Ctx crypto = Crypto.ctxForRepo(first, passFrom(a));

                List<RepoVolume> attached = new ArrayList<>();
                attached.add(first);
                LOG.info("Starting restore (dest=%s, snapshot=%s, unionLatest=%s, onlyFile=%s, onlyPrefix=%s)",
                        dest, snapshot, unionLatest, onlyFile, onlyPrefix);
                Restore.run(attached, snapshot, unionLatest, dest, crypto, onlyFile, onlyPrefix);
            }
            case "restore-plan" -> {
                Path idxPath = mustPath(a, "--global-index");
                Path repo = a.containsKey("--repo") ? mustPath(a, "--repo") : null;
                String snapshot = a.get("--snapshot");
                Path manifest = a.containsKey("--manifest") ? mustPath(a, "--manifest") : null;
                String onlyFile = a.get("--only-file");
                String onlyPrefix = a.get("--only-prefix");
                Integer maxDrives = a.containsKey("--max-drives") ? Integer.valueOf(a.get("--max-drives")) : null;
                String pass = passFrom(a);

                Planner.planWithGlobalIndex(idxPath, repo, snapshot, manifest, onlyFile, onlyPrefix, pass, maxDrives);
            }
            case "index-compact" -> {
                Path idxPath = mustPath(a, "--global-index");
                GlobalIndex gidx = GlobalIndex.open(idxPath, null, null, null, null);
                LOG.info("Compacting global index at %s ...", idxPath.toAbsolutePath());
                gidx.compact();
                LOG.info("Index compaction complete.");
            }
            case "inventory" -> {
                String mode = a.getOrDefault("--mode","scan");
                switch (mode) {
                    case "scan" -> {
                        Path repo = mustPath(a, "--repo");
                        Path invDir = mustPath(a, "--inventory");
                        RepoVolume v = RepoVolume.openOrInit(repo, null,8,2,262144,1048576,4194304,false,false,false,false);
                        Inventory.scanDrive(v, invDir, pInt(a.getOrDefault("--bpe","10")));
                    }
                    case "list" -> {
                        Path invDir = mustPath(a, "--inventory");
                        Inventory.list(invDir, a.get("--repo"));
                    }
                    case "locate" -> {
                        Path invDir = mustPath(a, "--inventory");
                        String chunkHex = a.get("--chunk");
                        if (chunkHex==null || chunkHex.length()!=64) throw new IllegalArgumentException("--chunk <sha256hex> required");
                        Inventory.locate(invDir, chunkHex, a.get("--repo"));
                    }
                    case "suggest" -> {
                        Path invDir = mustPath(a, "--inventory");
                        Path repo = a.containsKey("--repo") ? mustPath(a, "--repo") : null;
                        String snapshot = a.get("--snapshot");
                        Path manifest = a.containsKey("--manifest") ? mustPath(a, "--manifest") : null;
                        String onlyFile = a.get("--only-file");
                        String onlyPrefix = a.get("--only-prefix");
                        Integer maxDrives = a.containsKey("--max-drives") ? Integer.valueOf(a.get("--max-drives")) : null;
                        String pass = passFrom(a);
                        Inventory.suggest(invDir, repo, snapshot, manifest, onlyFile, onlyPrefix, pass, maxDrives);
                    }
                    default -> { System.out.println("inventory modes: --mode scan|list|locate|suggest"); }
                }
            }
            case "xparity-sweep" -> {
                Path repo = mustPath(a, "--repo");
                boolean finalizePartial = Boolean.parseBoolean(a.getOrDefault("--xfile-finalize-partial","true"));
                RepoVolume v = RepoVolume.openOrInit(repo, null,8,2,262144,1048576,4194304,false,false,false,false);
                Crypto.Ctx crypto = Crypto.ctxForRepo(v, passFrom(a));
                Backup.crossFileParitySweep(v, crypto, finalizePartial);
            }
            default -> usage();
        }
    }

    private static String passFrom(Map<String,String> a) throws IOException {
        String p = a.get("--passphrase");
        if (p!=null && !p.isBlank()) return p;
        String env = System.getenv("COLDSTORE_PASSPHRASE");
        if (env!=null && !env.isBlank()) return env;
        return null;
    }

    private static void usage() {
        System.out.println("""
        ColdStore — FastCDC + cross-drive dedupe + Reed–Solomon parity
        New: cross-file parity packer (--xfile-parity)

        Commands:
          init    --repo <path> [--name <RepoName>]
                  [--rs-k 8 --rs-r 2]
                  [--min-chunk 262144 --avg-chunk 1048576 --max-chunk 4194304]
                  [--compress false]
                  [--encrypt false] [--obfuscate-parity <true|false>]
                  [--encrypt-manifest <true|false>]
                  [--passphrase "..."] [--log info]

          info    --repo <path> [--log info]
          list    --repo <path> [--log info]

          backup  --repo <path> --source <path>
                  [--global-index <fileOrDir>]
                  [--xfile-parity true|false]              # cross-file parity (default false)
                  [--xfile-finalize-partial true|false]    # default true
                  [--target-bytes N]                       # hard byte cap (new chunks only)
                  [--target-fill 0.70]                     # % free-space cap (new chunks only)
                  [--passphrase "..."] [--log off|info|debug|trace]

          restore --repo <path> --dest <path> [--snapshot SNAP_...] [--union-latest true|false]
                  [--only-file <relpath>] [--only-prefix <relfolder/>]
                  [--passphrase "..."] [--log off|info|debug|trace]

          restore-plan --global-index <fileOrDir> [--repo <path>] [--snapshot SNAP_... | --manifest <path>]
                       [--only-file <relpath>] [--only-prefix <relfolder/>] [--max-drives N]
                       [--passphrase "..."]

          index-compact --global-index <fileOrDir> [--log info]

          inventory --mode scan   --repo <path> --inventory <dir> [--bpe 10]
                    --mode list   --inventory <dir> [--repo <path>]
                    --mode locate --inventory <dir> --chunk <sha256hex> [--repo <path>]
                    --mode suggest --inventory <dir> [--repo <path>] [--snapshot SNAP_... | --manifest <path>]
                                   [--only-file <relpath>] [--only-prefix <relfolder/>]
                                   [--max-drives N] [--passphrase "..."]

          xparity-sweep --repo <path> [--xfile-finalize-partial true|false]
                        [--passphrase "..."] [--log info]

        Notes:
          - Cross-file parity writes stripes under parity_xfile/stripe-XXXXXXXX/.
          - A small xfile_index.txt maps chunkId -> (stripeId,position) for fast repair.
          - When --xfile-parity=true, per-file parity is disabled.
          - Effective write cap = min(target-bytes, target-fill × freeAtStart). Parity/metadata are not counted in the cap.
        """);
    }

    private static Map<String,String> parseArgs(String[] args) {
        Map<String,String> m = new LinkedHashMap<>();
        if (args.length > 0) m.put("_cmd", args[0]);
        for (int i=1; i<args.length; i++) {
            String s=args[i];
            if (s.startsWith("--")) {
                String v = (i+1<args.length && !args[i+1].startsWith("--")) ? args[++i] : "true";
                m.put(s,v);
            }
        }
        return m;
    }
    private static Path mustPath(Map<String,String> a, String key) {
        String s = a.get(key);
        if (s==null) throw new IllegalArgumentException(key+" required");
        return Paths.get(s).toAbsolutePath().normalize();
    }
    private static int pInt(String s){ return Integer.parseInt(s.replace("_","")); }
    private static long pLong(String s){ return Long.parseLong(s.replace("_","")); }
    private static double pDouble(String s){ return Double.parseDouble(s.replace("_","")); }

    // ================= Repo =================

    static final class RepoProps {
        final String repoName;
        final String repoId;
        final String driveId;
        final int rsK, rsR, cMin, cAvg, cMax;
        final boolean compress;
        final boolean encrypt;
        final boolean obfuscateParity;
        final boolean encryptManifest;
        RepoProps(String repoName, String repoId, String driveId, int rsK,int rsR,int cMin,int cAvg,int cMax,
                  boolean compress, boolean encrypt, boolean obfuscateParity, boolean encryptManifest) {
            this.repoName=repoName; this.repoId=repoId; this.driveId=driveId;
            this.rsK=rsK; this.rsR=rsR; this.cMin=cMin; this.cAvg=cAvg; this.cMax=cMax;
            this.compress=compress; this.encrypt=encrypt; this.obfuscateParity=obfuscateParity; this.encryptManifest=encryptManifest;
        }
    }

    static final class RepoVolume {
        final Path root, propsFile, keyFile, chunksDir, parityDir, manifestsDir, chunkCatalog, snapIndex;
        final Path xparityDir, xfileIndex, xfileState;
        final RepoProps props;

        static RepoVolume openOrInit(Path root, String nameOrNull, int k,int r,int cMin,int cAvg,int cMax,
                                     boolean compress, boolean encrypt, boolean obfParity, boolean encManifest) throws IOException {
            Files.createDirectories(root);
            Path propsFile = root.resolve("repo.properties");
            RepoProps props;
            if (Files.exists(propsFile)) {
                Properties p = new Properties();
                try (InputStream in = Files.newInputStream(propsFile)) { p.load(in); }
                String nm = p.getProperty("repoName");
                String rid = p.getProperty("repo.id");
                String did = p.getProperty("drive.id");
                boolean changed = false;
                if (rid == null) { rid = UUID.randomUUID().toString(); p.setProperty("repo.id", rid); changed = true; }
                if (did == null) { did = UUID.randomUUID().toString(); p.setProperty("drive.id", did); changed = true; }
                if (changed) try (OutputStream out = Files.newOutputStream(propsFile, StandardOpenOption.TRUNCATE_EXISTING)) { p.store(out, "ColdStore Repo"); }

                if (nameOrNull!=null && !nameOrNull.equals(nm)) LOG.debug("Ignoring --name; existing repo name is %s", nm);
                props = new RepoProps(
                        nm, rid, did,
                        Integer.parseInt(p.getProperty("rs.k","8")),
                        Integer.parseInt(p.getProperty("rs.r","2")),
                        Integer.parseInt(p.getProperty("cdc.min","262144")),
                        Integer.parseInt(p.getProperty("cdc.avg","1048576")),
                        Integer.parseInt(p.getProperty("cdc.max","4194304")),
                        Boolean.parseBoolean(p.getProperty("compress","false")),
                        Boolean.parseBoolean(p.getProperty("encrypt","false")),
                        Boolean.parseBoolean(p.getProperty("parity.obfuscate", "false")),
                        Boolean.parseBoolean(p.getProperty("manifest.encrypt","false"))
                );
            } else {
                String nm = (nameOrNull!=null ? nameOrNull : "Repo");
                String rid = UUID.randomUUID().toString();
                String did = UUID.randomUUID().toString();
                props = new RepoProps(nm, rid, did, k,r,cMin,cAvg,cMax, compress, encrypt, obfParity, encManifest);
                Properties p = new Properties();
                p.setProperty("repoName", nm);
                p.setProperty("repo.id", rid);
                p.setProperty("drive.id", did);
                p.setProperty("rs.k", String.valueOf(k));
                p.setProperty("rs.r", String.valueOf(r));
                p.setProperty("cdc.min", String.valueOf(cMin));
                p.setProperty("cdc.avg", String.valueOf(cAvg));
                p.setProperty("cdc.max", String.valueOf(cMax));
                p.setProperty("compress", String.valueOf(compress));
                p.setProperty("encrypt", String.valueOf(encrypt));
                p.setProperty("parity.obfuscate", String.valueOf(obfParity));
                p.setProperty("manifest.encrypt", String.valueOf(encManifest));
                try (OutputStream out = Files.newOutputStream(propsFile, StandardOpenOption.CREATE_NEW)) { p.store(out, "ColdStore Repo"); }
            }
            RepoVolume v = new RepoVolume(root, propsFile, props);
            v.ensureLayout();
            return v;
        }

        private RepoVolume(Path root, Path propsFile, RepoProps props) {
            this.root=root; this.propsFile=propsFile; this.props=props;
            this.keyFile = root.resolve("key.enc");
            this.chunksDir = root.resolve("chunks");
            this.parityDir = root.resolve("parity");
            this.manifestsDir = root.resolve("manifests");
            this.chunkCatalog = root.resolve("chunk_catalog.txt");
            this.snapIndex = root.resolve("snapshots.txt");
            this.xparityDir = root.resolve("parity_xfile");
            this.xfileIndex = root.resolve("xfile_index.txt");
            this.xfileState = root.resolve("xfile_state.txt");
        }

        void ensureLayout() throws IOException {
            Files.createDirectories(chunksDir);
            Files.createDirectories(parityDir);
            Files.createDirectories(manifestsDir);
            Files.createDirectories(xparityDir);
            if (!Files.exists(chunkCatalog)) Files.createFile(chunkCatalog);
            if (!Files.exists(snapIndex)) Files.createFile(snapIndex);
            if (!Files.exists(xfileIndex)) Files.createFile(xfileIndex);
        }

        void showInfo() throws IOException {
            System.out.println("Repo: " + props.repoName + " (repo.id=" + props.repoId + "  drive.id=" + props.driveId + ")");
            System.out.println("Encrypt(chunks/parity): "+props.encrypt+"  Compress: "+props.compress);
            System.out.println("Parity-Obfuscate: "+props.obfuscateParity+"  Manifest-Encrypt: "+props.encryptManifest);
            System.out.println("RS: k="+props.rsK+" r="+props.rsR);
            System.out.println("CDC: min="+props.cMin+" avg="+props.cAvg+" max="+props.cMax);
            System.out.println("Root: " + root);
            System.out.println("Snapshots on this drive:");
            listSnapshots();
        }

        void listSnapshots() throws IOException {
            List<String> names = new ArrayList<>();
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(manifestsDir)) {
                for (Path p : ds) {
                    String fn = p.getFileName().toString();
                    if (fn.endsWith(".jsonl")) names.add(fn.substring(0, fn.length()-6));
                    else if (fn.endsWith(".jsonl.gcm")) names.add(fn.substring(0, fn.length()-10));
                }
            }
            Collections.sort(names);
            for (String n: names) System.out.println("  " + n);
            if (names.isEmpty()) System.out.println("  (none)");
        }

        Path chunkPath(byte[] sha){
            String h=hex(sha);
            return chunksDir.resolve(h.substring(0,2)).resolve(h.substring(2,4)).resolve(h);
        }
        Path parityStripeDir(String snapshot, String fileIdHash, int stripeIndex){
            return parityDir.resolve(snapshot).resolve(fileIdHash).resolve(String.format("stripe-%08d", stripeIndex));
        }

        Path xfileStripeDir(long stripeId){
            return xparityDir.resolve(String.format("stripe-%08d", stripeId));
        }

        Path manifestPlainPath(String snapshot){ return manifestsDir.resolve(snapshot + ".jsonl"); }
        Path manifestEncPath(String snapshot){ return manifestsDir.resolve(snapshot + ".jsonl.gcm"); }
        boolean hasEncManifest(String snapshot){ return Files.exists(manifestEncPath(snapshot)); }
        boolean hasPlainManifest(String snapshot){ return Files.exists(manifestPlainPath(snapshot)); }
    }

    // ================= Backup =================

    static final class Backup {
        static void runBackup(RepoVolume vol, Path source, String snapshotName,
                              long targetBytesArg, double targetFill,
                              GlobalIndex gidx, Crypto.Ctx crypto,
                              boolean xfileParity, boolean xfileFinalize) throws Exception {

            long freeAtStart = Files.getFileStore(vol.root).getUsableSpace();
            long fillCap = (targetFill > 0.0 && targetFill <= 1.0) ? (long)Math.floor(freeAtStart * targetFill) : Long.MAX_VALUE;
            long targetBytes = Math.min(targetBytesArg, fillCap);
            if (targetBytes == Long.MAX_VALUE) {
                LOG.info("No write cap set (consider --target-fill 0.70 or --target-bytes N). Free at start: %s", hb(freeAtStart));
            } else {
                LOG.info("Effective write cap (new chunks only): %s  [freeAtStart=%s, target-fill=%s, target-bytes=%s]",
                        hb(targetBytes), hb(freeAtStart),
                        (targetFill>0? String.format(Locale.ROOT,"%.2f%%", targetFill*100): "n/a"),
                        (targetBytesArg==Long.MAX_VALUE? "n/a" : hb(targetBytesArg)));
            }

            Files.createDirectories(vol.manifestsDir);
            Path manifestPlain = vol.manifestPlainPath(snapshotName);
            if (Files.exists(manifestPlain)) throw new IOException("Manifest already exists: " + manifestPlain);
            Path manifestTmp = manifestPlain.resolveSibling(manifestPlain.getFileName().toString()+".tmp");

            XFileParityPacker xpack = null;
            if (xfileParity) {
                xpack = new XFileParityPacker(vol, crypto, vol.props.rsK, vol.props.rsR, xfileFinalize);
                LOG.info("Cross-file parity enabled (K=%d, R=%d, finalizePartial=%s). Per-file parity will be skipped.", vol.props.rsK, vol.props.rsR, xfileFinalize);
            }

            try (BufferedWriter mw = Files.newBufferedWriter(manifestTmp, StandardOpenOption.CREATE_NEW)) {
                Counters c = new Counters();
                long newChunkBytesWritten = 0;

                Deque<Path> dq = new ArrayDeque<>();
                dq.add(source);
                FILES: while (!dq.isEmpty()) {
                    Path p = dq.removeFirst();
                    if (Files.isDirectory(p) && !Files.isSymbolicLink(p)) {
                        LOG.trace("Scanning directory: %s", p);
                        try (DirectoryStream<Path> ds = Files.newDirectoryStream(p)) {
                            for (Path ch : ds) dq.addLast(ch);
                        }
                        continue;
                    }
                    if (!Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)) continue;

                    long fileSize = Files.size(p);
                    String rel = source.toAbsolutePath().normalize().relativize(p.toAbsolutePath().normalize()).toString();
                    LOG.info("File: %s (%s)", rel, hb(fileSize));

                    List<String> chunkIds = new ArrayList<>();
                    List<Integer> chunkSizes = new ArrayList<>();

                    boolean capReached = false;
                    FastCDCStream cdc = new FastCDCStream(vol.props.cMin, vol.props.cAvg, vol.props.cMax);
                    try (InputStream in = Files.newInputStream(p)) {
                        ByteArrayOutputStream chunkBuf = new ByteArrayOutputStream(vol.props.cMax + 16);
                        int b, chunkIdx = 0, bytesThisChunk = 0;
                        while ((b=in.read())!=-1) {
                            cdc.update(b & 0xFF);
                            chunkBuf.write(b);
                            bytesThisChunk++;
                            if (cdc.shouldCut()) {
                                LOG.debug("  CHUNK cut: index=%d size=%s", chunkIdx, hb(bytesThisChunk));
                                long wrote = processChunk(vol, chunkBuf, chunkIds, chunkSizes, c, gidx, crypto, xpack);
                                newChunkBytesWritten += wrote;
                                LOG.trace("  CHUNK done: id=%s wrote=%s (cap=%s)", chunkIds.get(chunkIds.size()-1), hb(wrote), hb(targetBytes));
                                cdc.resetForNextChunk();
                                chunkIdx++; bytesThisChunk = 0;

                                if (newChunkBytesWritten >= targetBytes) {
                                    LOG.info("Target cap reached on this drive (new chunk bytes): %s", hb(newChunkBytesWritten));
                                    capReached = true;
                                    break;
                                }
                            }
                        }
                        if (!capReached && chunkBuf.size()>0) {
                            LOG.debug("  CHUNK cut (final): index=%d size=%s", chunkIds.size(), hb(chunkBuf.size()));
                            long wrote = processChunk(vol, chunkBuf, chunkIds, chunkSizes, c, gidx, crypto, xpack);
                            newChunkBytesWritten += wrote;
                            LOG.trace("  CHUNK done: id=%s wrote=%s (cap=%s)", chunkIds.get(chunkIds.size()-1), hb(wrote), hb(targetBytes));
                        }
                    }

                    if (!xfileParity) { // per-file parity only if cross-file is off
                        writePerFileParity(vol, snapshotName, rel, chunkIds, chunkSizes, c, crypto);
                    }

                    mw.write("{\"path\":\""+jesc(rel)+"\",\"bytes\":"+fileSize+",\"chunks\":[");
                    for (int i=0;i<chunkIds.size();i++){
                        if (i>0) mw.write(",");
                        mw.write("\""+chunkIds.get(i)+"\"");
                    }
                    mw.write("]}\n");
                    mw.flush();

                    if (newChunkBytesWritten >= targetBytes) break FILES;
                }

                if (xpack != null) xpack.close(); // flush pending (per flag)

                try (FileChannel ch = FileChannel.open(vol.snapIndex, StandardOpenOption.APPEND)) {
                    ch.write(ByteBuffer.wrap((snapshotName+"\n").getBytes()));
                    ch.force(true);
                }

                Files.move(manifestTmp, manifestPlain, StandardCopyOption.ATOMIC_MOVE);
                if (vol.props.encryptManifest) {
                    Path enc = vol.manifestEncPath(snapshotName);
                    LOG.info("Encrypting manifest -> %s", enc.getFileName());
                    Crypto.encryptFile(manifestPlain, enc, crypto, Crypto.MANIFEST_MAGIC);
                    Files.deleteIfExists(manifestPlain);
                }

                LOG.info("Backup complete on this drive: snapshot=%s", snapshotName);
            } finally {
                Files.deleteIfExists(manifestTmp);
            }
        }

        /** Returns bytes actually written for NEW chunk (post-compress/encrypt). Returns 0 on dedupe or already-present. */
        private static long processChunk(RepoVolume vol, ByteArrayOutputStream buf, List<String> chunkIds, List<Integer> chunkSizes,
                                         Counters c, GlobalIndex gidx, Crypto.Ctx crypto, XFileParityPacker xpack) throws Exception {
            byte[] raw = buf.toByteArray();
            buf.reset();
            byte[] sha = sha256(raw);
            String cidHex = hex(sha);

            if (gidx != null) {
                boolean in = gidx.contains(sha);
                LOG.trace("    IDX check: %s -> %s", cidHex.substring(0,16), in ? "present" : "absent");
                if (in) {
                    chunkIds.add(cidHex);
                    chunkSizes.add(raw.length);
                    c.reusedChunks++;
                    LOG.debug("    SKIP write (cross-drive dedupe): %s", cidHex.substring(0,16));
                    return 0L;
                }
            }

            Path dest = vol.chunkPath(sha);
            if (Files.exists(dest)) {
                c.reusedChunks++;
                LOG.debug("    REUSE (exists on this drive): %s", dest);
                chunkIds.add(cidHex);
                chunkSizes.add(raw.length);
                return 0L;
            }

            Files.createDirectories(dest.getParent());
            Path tmp = dest.resolveSibling(dest.getFileName().toString()+".tmp");

            byte[] payload = vol.props.compress ? gzip(raw) : raw;
            if (crypto.enabledForChunks()) payload = crypto.encryptWithMagic(payload, Crypto.CHUNK_MAGIC);

            try (OutputStream out = Files.newOutputStream(tmp, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                out.write(payload);
            }
            try { Files.move(tmp, dest, StandardCopyOption.ATOMIC_MOVE); } catch (FileAlreadyExistsException e) { Files.deleteIfExists(tmp); }
            try (FileChannel ch = FileChannel.open(dest, StandardOpenOption.READ)) { ch.force(true); }
            long sz = Files.size(dest);
            try (FileChannel ch = FileChannel.open(vol.chunkCatalog, StandardOpenOption.APPEND)) {
                ch.write(ByteBuffer.wrap((cidHex+"\t"+sz+"\n").getBytes()));
                ch.force(true);
            }
            c.newChunks++; c.bytesWritten+=sz;
            LOG.debug("    WRITE chunk: id=%s stored=%s at %s", cidHex.substring(0,16), hb(sz), dest);
            if (gidx != null) { gidx.add(sha, gidx.currentDriveOrdinal()); LOG.trace("    IDX add (driveOrd=%d): %s", gidx.currentDriveOrdinal(), cidHex.substring(0,16)); }

            // Cross-file parity feed (only for newly written chunks on this drive)
            if (xpack != null) {
                xpack.addChunk(cidHex, dest);
            }

            chunkIds.add(cidHex);
            chunkSizes.add(raw.length);
            return sz;
        }

        /** Legacy per-file parity — skipped when cross-file parity is enabled. */
        private static void writePerFileParity(RepoVolume vol, String snapshot, String relPath,
                                               List<String> chunkIds, List<Integer> sizes, Counters c, Crypto.Ctx crypto) throws Exception {
            int K = vol.props.rsK, R = vol.props.rsR;
            if (K<=0 || R<=0) return;

            String fileIdHash = crypto.fileIdHash(vol.props, relPath);
            ReedSolomon rs = new ReedSolomon(K, R);

            for (int base=0, stripeIdx=0; base<chunkIds.size(); base+=K, stripeIdx++) {
                int end = Math.min(base+K, chunkIds.size());

                boolean allLocal = true;
                for (int i=base;i<end;i++) {
                    String cid = chunkIds.get(i);
                    Path path = vol.chunkPath(unhex(cid));
                    if (!Files.exists(path)) { allLocal = false; break; }
                }
                if (!allLocal) {
                    LOG.trace("  PARITY skip (not all shards local): file=%s stripe=%d", relPath, stripeIdx);
                    continue;
                }

                List<byte[]> data = new ArrayList<>();
                int maxLen = 0;
                for (int i=base;i<end;i++) {
                    String cid = chunkIds.get(i);
                    Path path = vol.chunkPath(unhex(cid));
                    byte[] raw = readPayload(path, crypto, true);
                    data.add(raw);
                    maxLen = Math.max(maxLen, raw.length);
                }
                while (data.size()<K) data.add(new byte[0]);

                byte[][] dataAligned = new byte[K][maxLen];
                int[] realSizes = new int[K];
                for (int i=0;i<K;i++){ byte[] src = data.get(i); realSizes[i] = src.length; System.arraycopy(src,0,dataAligned[i],0,src.length); }

                byte[][] parity = new byte[R][maxLen];
                rs.encode(dataAligned, parity);

                Path sdir = vol.parityStripeDir(snapshot, fileIdHash, stripeIdx);
                Files.createDirectories(sdir);

                long totalParity = 0;
                for (int pi=0; pi<R; pi++) {
                    Path pf = sdir.resolve("p_"+pi);
                    byte[] outBytes = parity[pi];
                    if (crypto.enabledForChunks()) outBytes = crypto.encryptWithMagic(outBytes, Crypto.CHUNK_MAGIC);
                    try (OutputStream os = Files.newOutputStream(pf, StandardOpenOption.CREATE_NEW)) { os.write(outBytes); }
                    try (FileChannel ch = FileChannel.open(pf, StandardOpenOption.READ)) { ch.force(true); }
                    long sz = Files.size(pf);
                    c.bytesWritten += sz; totalParity += sz;
                }

                StringBuilder sb = new StringBuilder();
                sb.append("{\"k\":").append(K).append(",\"r\":").append(R).append(",\"chunks\":[");
                for (int i=0;i<K;i++){ if (i>0) sb.append(','); String cid=(base+i<chunkIds.size())?chunkIds.get(base+i):""; sb.append('"').append(cid).append('"'); }
                sb.append("],\"sizes\":[");
                for (int i=0;i<K;i++){ if (i>0) sb.append(','); int sizeVal=(base+i<chunkIds.size())?sizes.get(base+i):0; sb.append(sizeVal); }
                sb.append("]}");
                Path sidecar = sdir.resolve("sidecar.json");
                try (BufferedWriter bw = Files.newBufferedWriter(sidecar, StandardOpenOption.CREATE_NEW)) { bw.write(sb.toString()); }
                try (FileChannel ch = FileChannel.open(sidecar, StandardOpenOption.READ)) { ch.force(true); }

                LOG.debug("  PARITY stripe (per-file): file=%s stripe=%d shards=%d+%d shardSize=%s dir=%s totalWritten=%s",
                        relPath, stripeIdx, K, R, hb(maxLen), sdir, hb(totalParity));
            }
        }

        /** Backfill cross-file parity for all chunks already present on a drive. */
        static void crossFileParitySweep(RepoVolume vol, Crypto.Ctx crypto, boolean finalizePartial) throws Exception {
            XFileParityPacker xpack = new XFileParityPacker(vol, crypto, vol.props.rsK, vol.props.rsR, finalizePartial);
            LOG.info("Starting cross-file parity sweep (K=%d, R=%d, finalizePartial=%s)", vol.props.rsK, vol.props.rsR, finalizePartial);
            long n=0;
            try (BufferedReader br = Files.newBufferedReader(vol.chunkCatalog)) {
                String s;
                while ((s=br.readLine())!=null) {
                    int t = s.indexOf('\t');
                    if (t<0) continue;
                    String hex = s.substring(0,t);
                    if (hex.length()!=64) continue;
                    Path p = vol.chunkPath(unhex(hex));
                    if (Files.exists(p)) {
                        xpack.addChunk(hex, p);
                        if ((++n % 1_000_000)==0) LOG.info("  ... %,d chunks fed", n);
                    }
                }
            }
            xpack.close();
            LOG.info("Cross-file parity sweep complete. Chunks processed: %,d", n);
        }

        static final class Counters { long newChunks=0, reusedChunks=0, bytesWritten=0; }
    }

    // ================= Cross-file Parity Packer =================

    static final class XFileParityPacker implements Closeable {
        private final RepoVolume vol;
        private final Crypto.Ctx crypto;
        private final int K, R;
        private final ReedSolomon rs;
        private final boolean finalizePartial;
        private final List<String> chunkIds = new ArrayList<>();
        private final List<byte[]> data = new ArrayList<>();
        private final List<Integer> sizes = new ArrayList<>();
        private int maxLen = 0;
        private long nextStripeId = 0;

        XFileParityPacker(RepoVolume vol, Crypto.Ctx crypto, int K, int R, boolean finalizePartial) throws IOException {
            if (K<=0 || R<=0) throw new IllegalArgumentException("RS(K,R) must be > 0");
            this.vol = vol; this.crypto = crypto; this.K=K; this.R=R; this.finalizePartial = finalizePartial;
            this.rs = new ReedSolomon(K, R);
            this.nextStripeId = loadNextStripeId();
            loadPendingFromState(); // may prefill partial
        }

        void addChunk(String cidHex, Path chunkPath) throws Exception {
            byte[] raw = readPayload(chunkPath, crypto, true);
            chunkIds.add(cidHex);
            data.add(raw);
            sizes.add(raw.length);
            maxLen = Math.max(maxLen, raw.length);

            if (chunkIds.size() == K) flushStripe();
        }

        @Override public void close() throws IOException {
            try {
                if (!chunkIds.isEmpty()) {
                    if (finalizePartial) {
                        LOG.info("Finalizing short stripe with %d/%d chunks", chunkIds.size(), K);
                        flushStripe();
                    } else {
                        LOG.info("Carrying over short stripe with %d/%d chunks", chunkIds.size(), K);
                        savePendingToState();
                    }
                } else {
                    // clear any prior pending (nothing to carry)
                    clearPendingInState();
                }
            } catch (Exception e){ throw new IOException("Failed flushing cross-file parity", e); }
        }

        private void flushStripe() throws Exception {
            // Align to maxLen
            byte[][] dataAligned = new byte[K][maxLen];
            for (int i=0;i<K;i++){
                byte[] src = (i<data.size()? data.get(i) : new byte[0]);
                System.arraycopy(src, 0, dataAligned[i], 0, Math.min(src.length, maxLen));
            }

            // Compute parity
            byte[][] parity = new byte[R][maxLen];
            rs.encode(dataAligned, parity);

            // Write stripe
            Path sdir = vol.xfileStripeDir(nextStripeId);
            Files.createDirectories(sdir);

            long totalParity = 0;
            for (int pi=0; pi<R; pi++) {
                Path pf = sdir.resolve("p_"+pi);
                byte[] outBytes = parity[pi];
                if (crypto.enabledForChunks()) outBytes = crypto.encryptWithMagic(outBytes, Crypto.CHUNK_MAGIC);
                try (OutputStream os = Files.newOutputStream(pf, StandardOpenOption.CREATE_NEW)) { os.write(outBytes); }
                try (FileChannel ch = FileChannel.open(pf, StandardOpenOption.READ)) { ch.force(true); }
                totalParity += Files.size(pf);
            }

            // Sidecar
            StringBuilder sb = new StringBuilder();
            sb.append("{\"k\":").append(K).append(",\"r\":").append(R).append(",\"shardSize\":").append(maxLen).append(",\"chunks\":[");
            for (int i=0;i<K;i++){ if (i>0) sb.append(','); String cid=(i<chunkIds.size())?chunkIds.get(i):""; sb.append('"').append(cid).append('"'); }
            sb.append("],\"sizes\":[");
            for (int i=0;i<K;i++){ if (i>0) sb.append(','); int sz=(i<sizes.size())?sizes.get(i):0; sb.append(sz); }
            sb.append("]}");
            Path sidecar = sdir.resolve("sidecar.json");
            try (BufferedWriter bw = Files.newBufferedWriter(sidecar, StandardOpenOption.CREATE_NEW)) { bw.write(sb.toString()); }
            try (FileChannel ch = FileChannel.open(sidecar, StandardOpenOption.READ)) { ch.force(true); }

            // Index entries
            try (FileChannel ch = FileChannel.open(vol.xfileIndex, StandardOpenOption.APPEND)) {
                for (int i=0;i<chunkIds.size();i++) {
                    String line = chunkIds.get(i) + "\t" + nextStripeId + "\t" + i + "\n";
                    ch.write(ByteBuffer.wrap(line.getBytes()));
                }
                ch.force(true);
            }

            LOG.debug("XF-PARITY stripe: id=%d shards=%d+%d shardSize=%s dir=%s totalWritten=%s",
                    nextStripeId, K, R, hb(maxLen), sdir, hb(totalParity));

            // bump and clear
            nextStripeId++;
            saveNextStripeId();
            chunkIds.clear(); data.clear(); sizes.clear(); maxLen = 0;
            clearPendingInState();
        }

        private long loadNextStripeId() throws IOException {
            // prefer state file
            if (Files.exists(vol.xfileState)) {
                Properties p = new Properties();
                try (InputStream in = Files.newInputStream(vol.xfileState)) { p.load(in); }
                String nxt = p.getProperty("nextStripeId");
                if (nxt != null) return Long.parseLong(nxt);
            }
            // else scan existing stripes to pick max+1
            long max = -1;
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(vol.xparityDir, "stripe-*")) {
                for (Path s : ds) {
                    String fn = s.getFileName().toString();
                    int dash = fn.indexOf('-');
                    if (dash>=0) {
                        try { long id = Long.parseLong(fn.substring(dash+1)); if (id>max) max=id; } catch (NumberFormatException ignore) {}
                    }
                }
            }
            long next = max+1;
            saveNextStripeId(next);
            return next;
        }

        private void saveNextStripeId() throws IOException { saveNextStripeId(this.nextStripeId); }
        private void saveNextStripeId(long n) throws IOException {
            Properties p = new Properties();
            p.setProperty("nextStripeId", Long.toString(n));
            // also persist pending list if exists (handled elsewhere)
            try (OutputStream out = Files.newOutputStream(vol.xfileState, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                p.store(out, "Cross-file parity state");
            }
        }

        private void loadPendingFromState() throws IOException {
            if (!Files.exists(vol.xfileState)) return;
            Properties p = new Properties();
            try (InputStream in = Files.newInputStream(vol.xfileState)) { p.load(in); }
            String pend = p.getProperty("pending");
            if (pend==null || pend.isBlank()) return;
            LOG.info("Resuming short stripe with %d pending chunks", pend.split(",").length);
            for (String h : pend.split(",")) {
                h = h.trim();
                if (h.isEmpty()) continue;
                Path cp = vol.chunkPath(unhex(h));
                if (Files.exists(cp)) {
                    try {
                        byte[] raw = readPayload(cp, crypto, true);
                        chunkIds.add(h); data.add(raw); sizes.add(raw.length);
                        maxLen = Math.max(maxLen, raw.length);
                    } catch (Exception e) {
                        LOG.info("Skipping pending chunk %s (failed to read: %s)", h.substring(0,16), e.getMessage());
                    }
                }
            }
        }

        private void savePendingToState() throws IOException {
            Properties p = new Properties();
            p.setProperty("nextStripeId", Long.toString(nextStripeId));
            StringBuilder sb = new StringBuilder();
            for (int i=0;i<chunkIds.size();i++){ if (i>0) sb.append(','); sb.append(chunkIds.get(i)); }
            p.setProperty("pending", sb.toString());
            try (OutputStream out = Files.newOutputStream(vol.xfileState, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                p.store(out, "Cross-file parity state");
            }
        }
        private void clearPendingInState() throws IOException {
            if (!Files.exists(vol.xfileState)) return;
            Properties p = new Properties();
            try (InputStream in = Files.newInputStream(vol.xfileState)) { p.load(in); }
            p.remove("pending");
            try (OutputStream out = Files.newOutputStream(vol.xfileState, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                p.store(out, "Cross-file parity state");
            }
        }
    }

    // ================= Restore =================

    static final class Restore {

        static void run(List<RepoVolume> attached, String snapshot, boolean unionLatest, Path dest, Crypto.Ctx crypto,
                        String onlyFile, String onlyPrefix) throws Exception {
            Files.createDirectories(dest);
            if (unionLatest && snapshot != null) throw new IllegalArgumentException("Use either --snapshot or --union-latest, not both.");

            if (snapshot != null) {
                RepoVolume src = requireRepoWithSnapshot(attached, snapshot);
                restoreSnapshot(attached, src, snapshot, dest, crypto, onlyFile, onlyPrefix);
            } else if (unionLatest) {
                Set<String> done = new HashSet<>();
                for (;;) {
                    boolean progressed = false;
                    for (RepoVolume v : attached) {
                        String latest = latestSnapshot(v);
                        if (latest!=null && done.add(v.root.toString()+":"+latest)) {
                            LOG.info("Restoring latest from %s: %s", v.root, latest);
                            restoreSnapshot(attached, v, latest, dest, crypto, onlyFile, onlyPrefix);
                            progressed = true;
                        }
                    }
                    if (!progressed) break;
                    if (promptYesNo("Attach another repo drive and continue union restore? [y/N] ")) {
                        RepoVolume nv = promptAttachMore(attached.get(0).props.repoName);
                        if (nv!=null) attached.add(nv);
                    } else break;
                }
                LOG.info("Union restore complete.");
            } else {
                throw new IllegalArgumentException("Provide --snapshot SNAP_... or --union-latest true");
            }
        }

        private static void restoreSnapshot(List<RepoVolume> attached, RepoVolume manifestRepo, String snapshot, Path dest,
                                            Crypto.Ctx crypto, String onlyFile, String onlyPrefix) throws Exception {
            Path manifestPath = locateManifest(attached, snapshot);
            if (manifestPath == null) {
                LOG.info("Snapshot %s not found on attached drives.", snapshot);
                RepoVolume nv = promptAttachMore(manifestRepo.props.repoName);
                if (nv==null) throw new FileNotFoundException("Snapshot manifest not found.");
                attached.add(nv);
                restoreSnapshot(attached, nv, snapshot, dest, crypto, onlyFile, onlyPrefix);
                return;
            }

            LOG.info("Restoring snapshot %s using manifest at %s", snapshot, manifestPath);
            try (BufferedReader br = openManifestReader(manifestPath, crypto)) {
                String line;
                while ((line=br.readLine())!=null) {
                    String rel = extractJsonValue(line, "path");

                    // FILTERS
                    if (onlyFile != null && !onlyFile.isBlank() && !rel.equals(onlyFile)) continue;
                    if (onlyPrefix != null && !onlyPrefix.isBlank() && !rel.startsWith(onlyPrefix)) continue;

                    String chunksArr = extractArray(line, "chunks");
                    List<String> cids = chunksArr.isBlank() ? List.of() : Arrays.asList(chunksArr.split(","));
                    Path out = dest.resolve(rel);
                    Files.createDirectories(out.getParent());
                    LOG.debug("  Restore file: %s (chunks=%d)", rel, cids.size());

                    try (OutputStream os = Files.newOutputStream(out, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                        for (int idx=0; idx<cids.size(); idx++) {
                            String cid = stripQuotes(cids.get(idx));
                            byte[] chunk = findChunkAcross(attached, cid, crypto);
                            if (chunk != null) { LOG.trace("    found chunk: %s", cid.substring(0,16)); os.write(chunk); continue; }
                            byte[] repaired = recoverFromPerFileParity(attached, manifestRepo, snapshot, rel, idx, cids, crypto);
                            if (repaired != null) { LOG.debug("    repaired (per-file parity): %s", cid.substring(0,16)); os.write(repaired); continue; }
                            byte[] repairedX = recoverFromXFileParity(attached, cid, crypto);
                            if (repairedX != null) { LOG.debug("    repaired (cross-file parity): %s", cid.substring(0,16)); os.write(repairedX); continue; }
                            LOG.info("    missing chunk %s. Prompting for another drive...", cid.substring(0,16));
                            RepoVolume nv = promptAttachMore(manifestRepo.props.repoName);
                            if (nv==null) throw new FileNotFoundException("Unrecoverable: missing chunk "+cid);
                            attached.add(nv);
                            idx--;
                        }
                    }
                }
            }
            LOG.info("Snapshot restore complete: %s", snapshot);
        }

        private static Path locateManifest(List<RepoVolume> attached, String snapshot) {
            for (RepoVolume v : attached) {
                Path enc = v.manifestEncPath(snapshot);
                if (Files.exists(enc)) return enc;
                Path plain = v.manifestPlainPath(snapshot);
                if (Files.exists(plain)) return plain;
            }
            return null;
        }

        private static BufferedReader openManifestReader(Path manifestPath, Crypto.Ctx crypto) throws Exception {
            String fn = manifestPath.getFileName().toString();
            InputStream in = Files.newInputStream(manifestPath);
            if (fn.endsWith(".jsonl.gcm")) {
                in = crypto.decryptingInputStream(in, Crypto.MANIFEST_MAGIC);
            }
            return new BufferedReader(new InputStreamReader(in));
        }

        private static String latestSnapshot(RepoVolume v) throws IOException {
            List<String> names = new ArrayList<>();
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(v.manifestsDir)) {
                for (Path p : ds) {
                    String fn = p.getFileName().toString();
                    if (fn.endsWith(".jsonl")) names.add(fn.substring(0, fn.length()-6));
                    else if (fn.endsWith(".jsonl.gcm")) names.add(fn.substring(0, fn.length()-10));
                }
            }
            if (names.isEmpty()) return null;
            Collections.sort(names);
            return names.get(names.size()-1);
        }

        private static RepoVolume requireRepoWithSnapshot(List<RepoVolume> attached, String snapshot) throws Exception {
            Path p = locateManifest(attached, snapshot);
            if (p != null) return attached.stream().filter(v -> p.startsWith(v.root)).findFirst().orElse(attached.get(0));
            LOG.info("Snapshot %s not found on attached drives.", snapshot);
            RepoVolume nv = promptAttachMore(attached.get(0).props.repoName);
            if (nv==null) throw new FileNotFoundException("Snapshot manifest not found.");
            attached.add(nv);
            return requireRepoWithSnapshot(attached, snapshot);
        }

        private static byte[] findChunkAcross(List<RepoVolume> attached, String cid, Crypto.Ctx crypto) throws Exception {
            byte[] sha = unhex(cid);
            for (RepoVolume v: attached) {
                Path p = v.chunkPath(sha);
                if (Files.exists(p)) { LOG.trace("      locating chunk on %s", p); return readPayload(p, crypto, true); }
            }
            return null;
        }

        private static byte[] recoverFromPerFileParity(List<RepoVolume> attached, RepoVolume manifestRepo,
                                                String snapshot, String relPath, int chunkIndexInFile,
                                                List<String> cids, Crypto.Ctx crypto) throws Exception {
            int K = manifestRepo.props.rsK, R = manifestRepo.props.rsR;
            if (K<=0 || R<=0) return null;

            List<String> candidates = new ArrayList<>();
            candidates.add(hex(sha256(relPath.getBytes("UTF-8")))); // legacy
            if (crypto.anyCrypto()) candidates.add(crypto.hmacHex(relPath.getBytes("UTF-8"))); // obfuscated

            int stripeIdx = chunkIndexInFile / K;
            int missingIdx = chunkIndexInFile % K;

            Path sdir = null;
            for (RepoVolume v: attached) {
                for (String fileIdHash : candidates) {
                    Path candidate = v.parityStripeDir(snapshot, fileIdHash, stripeIdx);
                    if (Files.isDirectory(candidate) && Files.exists(candidate.resolve("sidecar.json"))) { sdir=candidate; break; }
                }
                if (sdir!=null) break;
            }
            if (sdir == null) return null;

            String sidecar = Files.readString(sdir.resolve("sidecar.json"));
            int k = Integer.parseInt(extractJsonValue(sidecar, "k"));
            int r = Integer.parseInt(extractJsonValue(sidecar, "r"));
            String idArr = extractArray(sidecar, "chunks");
            String szArr = extractArray(sidecar, "sizes");
            String[] ids = idArr.isBlank()? new String[0] : idArr.split(",");
            String[] szs = szArr.isBlank()? new String[0] : szArr.split(",");
            if (k != K || r != R) return null;

            byte[][] data = new byte[K][];
            int maxLen=0;
            for (int i=0;i<K;i++){
                String cid = stripQuotes(ids[i]);
                if (cid.isEmpty()) { data[i] = new byte[0]; }
                else {
                    byte[] bytes = findChunkAcross(attached, cid, crypto);
                    data[i] = (bytes!=null) ? bytes : new byte[0];
                    if (bytes!=null) maxLen=Math.max(maxLen, bytes.length);
                }
            }
            byte[][] dataAligned = new byte[K][maxLen];
            for (int i=0;i<K;i++) System.arraycopy(data[i],0,dataAligned[i],0,data[i].length);

            List<byte[]> parity = new ArrayList<>();
            for (int pi=0; pi<R; pi++) {
                Path pf = sdir.resolve("p_"+pi);
                if (Files.exists(pf)) parity.add(readPayload(pf, crypto, false));
            }
            if (parity.isEmpty()) return null;
            for (int i=0;i<parity.size();i++){
                if (parity.get(i).length!=maxLen){
                    byte[] exp = new byte[maxLen];
                    System.arraycopy(parity.get(i),0,exp,0,Math.min(parity.get(i).length,maxLen));
                    parity.set(i, exp);
                }
            }

            ReedSolomon rs = new ReedSolomon(K, parity.size());
            byte[] rec = rs.decodeSingle(dataAligned, parity, missingIdx);
            if (rec==null) return null;

            int trueSize = Integer.parseInt(stripQuotes(szs[missingIdx]));
            if (trueSize < rec.length) { byte[] trimmed = new byte[trueSize]; System.arraycopy(rec,0,trimmed,0,trueSize); return trimmed; }
            return rec;
        }

        /** Recover a missing chunk using cross-file parity. */
        private static byte[] recoverFromXFileParity(List<RepoVolume> attached, String cidHex, Crypto.Ctx crypto) throws Exception {
            // find stripe + position on any attached drive via xfile_index.txt
            for (RepoVolume v : attached) {
                if (!Files.exists(v.xfileIndex)) continue;
                long stripeId = -1; int pos = -1;
                try (BufferedReader br = Files.newBufferedReader(v.xfileIndex)) {
                    String s;
                    while ((s=br.readLine())!=null) {
                        int t1 = s.indexOf('\t'); if (t1<0) continue;
                        String h = s.substring(0,t1);
                        if (!h.equals(cidHex)) continue;
                        int t2 = s.indexOf('\t', t1+1); if (t2<0) continue;
                        stripeId = Long.parseLong(s.substring(t1+1, t2));
                        pos = Integer.parseInt(s.substring(t2+1).trim());
                        break;
                    }
                }
                if (stripeId<0 || pos<0) continue;

                Path sdir = v.xfileStripeDir(stripeId);
                Path sidecar = sdir.resolve("sidecar.json");
                if (!Files.exists(sidecar)) continue;
                String meta = Files.readString(sidecar);
                int K = Integer.parseInt(extractJsonValue(meta, "k"));
                int R = Integer.parseInt(extractJsonValue(meta, "r"));
                int shardSize = Integer.parseInt(extractJsonValue(meta, "shardSize"));
                String idArr = extractArray(meta, "chunks");
                String szArr = extractArray(meta, "sizes");
                String[] ids = idArr.isBlank()? new String[0] : idArr.split(",");
                String[] szs = szArr.isBlank()? new String[0] : szArr.split(",");

                // assemble data and parity
                byte[][] data = new byte[K][];
                int maxLen = shardSize;
                int missingIdx = pos;
                for (int i=0;i<K;i++){
                    String ch = stripQuotes(ids[i]);
                    if (i==missingIdx || ch.isEmpty()) { data[i] = new byte[0]; continue; }
                    Path p = v.chunkPath(unhex(ch));
                    if (Files.exists(p)) data[i] = readPayload(p, crypto, true);
                    else data[i] = new byte[0];
                }
                byte[][] dataAligned = new byte[K][maxLen];
                for (int i=0;i<K;i++) System.arraycopy(data[i],0,dataAligned[i],0,Math.min(data[i].length, maxLen));

                List<byte[]> parity = new ArrayList<>();
                for (int pi=0; pi<R; pi++) {
                    Path pf = sdir.resolve("p_"+pi);
                    if (Files.exists(pf)) parity.add(readPayload(pf, crypto, false));
                }
                if (parity.size()==0) continue;
                for (int i=0;i<parity.size();i++){
                    if (parity.get(i).length!=maxLen){
                        byte[] exp = new byte[maxLen];
                        System.arraycopy(parity.get(i),0,exp,0,Math.min(parity.get(i).length,maxLen));
                        parity.set(i, exp);
                    }
                }

                ReedSolomon rs = new ReedSolomon(K, parity.size());
                byte[] rec = rs.decodeSingle(dataAligned, parity, missingIdx);
                if (rec==null) continue;

                int trueSize = Integer.parseInt(stripQuotes(szs[missingIdx]));
                if (trueSize < rec.length) { byte[] trimmed = new byte[trueSize]; System.arraycopy(rec,0,trimmed,0,trueSize); return trimmed; }
                return rec;
            }
            return null;
        }

        private static RepoVolume promptAttachMore(String repoName) throws Exception {
            System.out.print("Attach another drive for repo '"+repoName+"'. Enter its --repo path (or blank to give up): ");
            BufferedReader r = new BufferedReader(new InputStreamReader(System.in));
            String line = r.readLine();
            if (line==null || line.isBlank()) return null;
            Path p = Paths.get(line.trim()).toAbsolutePath().normalize();
            if (!Files.isDirectory(p)) { System.out.println("Not a directory."); return null; }
            RepoVolume v = RepoVolume.openOrInit(p, null,8,2,262144,1048576,4194304,false,false,false,false);
            if (!v.props.repoName.equals(repoName)) { System.out.println("Repo name mismatch: expected "+repoName+" got "+v.props.repoName); return null; }
            LOG.info("Attached additional repo drive at %s", p);
            return v;
        }

        private static boolean promptYesNo(String msg) throws IOException {
            System.out.print(msg);
            BufferedReader r = new BufferedReader(new InputStreamReader(System.in));
            String s=r.readLine();
            return s!=null && (s.equalsIgnoreCase("y")||s.equalsIgnoreCase("yes"));
        }
    }

    // ================= Planner (restore plan via location-aware global index) =================

    static final class Planner {
        static void planWithGlobalIndex(Path idxPath, Path repoPathOrNull, String snapshot, Path manifestPathOrNull,
                                        String onlyFile, String onlyPrefix, String passphrase, Integer maxDrives) throws Exception {
            GlobalIndex gidx = GlobalIndex.open(idxPath, null, null, null, null);

            RepoVolume repoVol = null;
            Crypto.Ctx crypto = null;
            Path manifest = manifestPathOrNull;
            if (manifest == null) {
                if (repoPathOrNull == null || snapshot == null)
                    throw new IllegalArgumentException("Provide either --manifest, or both --repo and --snapshot");
                repoVol = RepoVolume.openOrInit(repoPathOrNull, null,8,2,262144,1048576,4194304,false,false,false,false);
                crypto = Crypto.ctxForRepo(repoVol, passphrase);
                if (repoVol.hasEncManifest(snapshot)) manifest = repoVol.manifestEncPath(snapshot);
                else if (repoVol.hasPlainManifest(snapshot)) manifest = repoVol.manifestPlainPath(snapshot);
                else throw new FileNotFoundException("Snapshot manifest not found on provided --repo");
            } else {
                if (repoPathOrNull != null) {
                    repoVol = RepoVolume.openOrInit(repoPathOrNull, null,8,2,262144,1048576,4194304,false,false,false,false);
                    crypto = Crypto.ctxForRepo(repoVol, passphrase);
                }
            }

            // Gather needed chunks
            List<String> needed = new ArrayList<>();
            try (BufferedReader br = openManifestReaderForPlanner(manifest, crypto)) {
                String line;
                while ((line=br.readLine())!=null) {
                    String rel = extractJsonValue(line, "path");
                    if (onlyFile != null && !onlyFile.isBlank() && !rel.equals(onlyFile)) continue;
                    if (onlyPrefix != null && !onlyPrefix.isBlank() && !rel.startsWith(onlyPrefix)) continue;
                    String arr = extractArray(line, "chunks");
                    if (!arr.isBlank()) for (String tok : arr.split(",")) needed.add(stripQuotes(tok));
                }
            }
            if (needed.isEmpty()) { System.out.println("No matching paths or chunks in manifest."); return; }

            // Tally by drive ordinal
            Map<Integer, Long> tally = new HashMap<>();
            long unknown = 0;
            for (String hex : needed) {
                int ord = gidx.location(unhex(hex));
                if (ord >= 0) tally.put(ord, tally.getOrDefault(ord,0L)+1);
                else unknown++;
            }

            // Sort drives by coverage
            List<Integer> ords = new ArrayList<>(tally.keySet());
            ords.sort((a,b)->Long.compare(tally.get(b), tally.get(a)));

            long covered = needed.size() - unknown;
            System.out.printf(Locale.ROOT, "Chunks needed: %,d   Known in index: %,d (%.2f%%)   Unknown: %,d%n",
                    needed.size(), covered, 100.0*covered/needed.size(), unknown);

            if (ords.isEmpty()) {
                System.out.println("No drive locations known in the index. Ensure you used --global-index during backups and ran index-compact occasionally.");
                return;
            }

            System.out.println("Suggested drive attach order (by chunk coverage):");
            int shown = 0;
            for (Integer ord : ords) {
                if (maxDrives!=null && shown>=maxDrives) break;
                String label = gidx.driveLabel(ord);
                String driveId = gidx.driveId(ord);
                long cnt = tally.get(ord);
                System.out.printf(Locale.ROOT, "  %d) ord=%d  chunks≈%,d  drive.id=%s  label=%s%n", ++shown, ord, cnt, driveId, label);
            }
            if (maxDrives!=null && ords.size()>maxDrives) {
                System.out.printf(Locale.ROOT, "...and %d more drives with smaller coverage%n", ords.size()-maxDrives);
            }
        }

        private static BufferedReader openManifestReaderForPlanner(Path manifestPath, Crypto.Ctx crypto) throws Exception {
            String fn = manifestPath.getFileName().toString();
            InputStream in = Files.newInputStream(manifestPath);
            if (fn.endsWith(".jsonl.gcm")) {
                if (crypto==null || crypto.master==null) throw new IOException("Encrypted manifest: provide --repo and --passphrase to decrypt.");
                in = crypto.decryptingInputStream(in, Crypto.MANIFEST_MAGIC);
            }
            return new BufferedReader(new InputStreamReader(in));
        }
    }

    // ================= Inventory (Bloom filters per drive; optional) =================

    static final class Inventory {
        private static final byte[] MAGIC = new byte[]{'C','S','I','V','1'};

        static void scanDrive(RepoVolume v, Path invDir, int bitsPerElement) throws IOException {
            Files.createDirectories(invDir);
            long n = countCatalogEntries(v.chunkCatalog);
            if (n==0) { System.out.println("No entries in chunk_catalog.txt on this drive."); return; }

            int mBits = Math.max(1<<20, nextPow2((int)Math.min(Integer.MAX_VALUE-8L, n * (long)bitsPerElement)));
            int k = Math.max(1, (int)Math.round((mBits / (double)n) * Math.log(2)));

            LOG.info("Building Bloom filter: entries≈%d, bits=%d (~%.1f MB), k=%d", n, mBits, (mBits/8.0/1024/1024), k);
            BloomFilter bf = new BloomFilter(mBits, k);

            try (BufferedReader br = Files.newBufferedReader(v.chunkCatalog)) {
                String s; long i=0;
                while ((s=br.readLine())!=null) {
                    int tab = s.indexOf('\t');
                    if (tab<0) continue;
                    String hex = s.substring(0, tab);
                    if (hex.length()!=64) continue;
                    bf.add(unhex(hex));
                    if ((++i % 1_000_000)==0) LOG.info("  ... %,d entries added", i);
                }
            }

            String base = v.props.repoName.replaceAll("[^A-Za-z0-9._-]","_") + "__" + v.props.driveId + ".inv";
            Path out = invDir.resolve(base);

            try (DataOutputStream dout = new DataOutputStream(new BufferedOutputStream(Files.newOutputStream(out, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)))) {
                dout.write(MAGIC);
                dout.writeUTF(v.props.repoId);
                dout.writeUTF(v.props.repoName);
                dout.writeUTF(v.props.driveId);
                dout.writeUTF(v.root.toString());
                dout.writeLong(Instant.now().getEpochSecond());
                dout.writeLong(n);
                dout.writeInt(bf.mBits);
                dout.writeInt(bf.k);
                dout.writeInt(bf.bits.length);
                dout.write(bf.bits);
            }
            LOG.info("Inventory written: %s", out);
        }

        static void list(Path invDir, String repoFilterPathOrNull) throws IOException {
            String repoIdFilter = null;
            if (repoFilterPathOrNull != null) {
                RepoVolume v = RepoVolume.openOrInit(Paths.get(repoFilterPathOrNull), null,8,2,262144,1048576,4194304,false,false,false,false);
                repoIdFilter = v.props.repoId;
            }
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(invDir, "*.inv")) {
                for (Path p : ds) {
                    Entry e = readEntry(p);
                    if (repoIdFilter!=null && !repoIdFilter.equals(e.repoId)) continue;
                    System.out.printf(Locale.ROOT, "%s  repo=%s  drive=%s  name=%s  entries≈%,d  bits=%,d  k=%d  date=%s%n",
                            p.getFileName(), e.repoId, e.driveId, e.repoName, e.nEntries, e.bf.mBits, e.bf.k,
                            Instant.ofEpochSecond(e.timestamp));
                }
            }
        }

        static void locate(Path invDir, String chunkHex, String repoFilterPathOrNull) throws IOException {
            byte[] key = unhex(chunkHex);
            String repoIdFilter = null;
            if (repoFilterPathOrNull != null) {
                RepoVolume v = RepoVolume.openOrInit(Paths.get(repoFilterPathOrNull), null,8,2,262144,1048576,4194304,false,false,false,false);
                repoIdFilter = v.props.repoId;
            }
            List<String> hits = new ArrayList<>();
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(invDir, "*.inv")) {
                for (Path p : ds) {
                    Entry e = readEntry(p);
                    if (repoIdFilter!=null && !repoIdFilter.equals(e.repoId)) continue;
                    if (e.bf.contains(key)) hits.add(e.label + " (drive.id="+e.driveId+")");
                }
            }
            if (hits.isEmpty()) System.out.println("No likely drives found.");
            else {
                System.out.println("Likely present on:");
                for (String s : hits) System.out.println("  - " + s);
            }
        }

        static void suggest(Path invDir, Path repoPathOrNull, String snapshot, Path manifestPathOrNull,
                            String onlyFile, String onlyPrefix, String passphrase, Integer maxDrives) throws Exception {
            RepoVolume repoVol = null;
            Crypto.Ctx crypto = null;
            String repoId = null;
            if (repoPathOrNull != null) {
                repoVol = RepoVolume.openOrInit(repoPathOrNull, null,8,2,262144,1048576,4194304,false,false,false,false);
                repoId = repoVol.props.repoId;
                crypto = Crypto.ctxForRepo(repoVol, passphrase);
            }

            Path manifestPath = manifestPathOrNull;
            if (manifestPath == null) {
                if (repoVol == null || snapshot == null) throw new IllegalArgumentException("Provide either --manifest or --repo with --snapshot");
                if (repoVol.hasEncManifest(snapshot)) manifestPath = repoVol.manifestEncPath(snapshot);
                else if (repoVol.hasPlainManifest(snapshot)) manifestPath = repoVol.manifestPlainPath(snapshot);
                else throw new FileNotFoundException("Snapshot manifest not found on provided --repo");
            }

            List<String> needed = new ArrayList<>();
            try (BufferedReader br = openManifestReaderForInventory(manifestPath, crypto)) {
                String line;
                while ((line=br.readLine())!=null) {
                    String rel = extractJsonValue(line, "path");
                    if (onlyFile != null && !onlyFile.isBlank() && !rel.equals(onlyFile)) continue;
                    if (onlyPrefix != null && !onlyPrefix.isBlank() && !rel.startsWith(onlyPrefix)) continue;
                    String arr = extractArray(line, "chunks");
                    if (!arr.isBlank()) for (String tok : arr.split(",")) needed.add(stripQuotes(tok));
                }
            }
            if (needed.isEmpty()) { System.out.println("No matching paths or chunks in manifest."); return; }

            List<Entry> entries = new ArrayList<>();
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(invDir, "*.inv")) {
                for (Path p : ds) {
                    Entry e = readEntry(p);
                    if (repoId!=null && !repoId.equals(e.repoId)) continue;
                    entries.add(e);
                }
            }
            if (entries.isEmpty()) { System.out.println("No inventory files found (or none matching repo.id)."); return; }

            Set<String> remaining = new HashSet<>(needed);
            List<Entry> order = new ArrayList<>();
            while (!remaining.isEmpty() && (maxDrives==null || order.size()<maxDrives)) {
                Entry best = null; int bestCover=0;
                for (Entry e : entries) {
                    if (order.contains(e)) continue;
                    int cover=0;
                    for (String hex : remaining) if (e.bf.contains(unhex(hex))) cover++;
                    if (cover>bestCover){ best=e; bestCover=cover; }
                }
                if (best==null || bestCover==0) break;
                order.add(best);
                Iterator<String> it = remaining.iterator();
                while (it.hasNext()){
                    String h = it.next();
                    if (best.bf.contains(unhex(h))) it.remove();
                }
            }

            long covered = needed.size() - remaining.size();
            System.out.printf(Locale.ROOT, "Chunks needed: %,d   Covered by plan: %,d (%.2f%%)   Drives chosen: %d%n",
                    needed.size(), covered, 100.0*covered/needed.size(), order.size());
            if (!order.isEmpty()) {
                System.out.println("Suggested drive attach order:");
                for (int i=0;i<order.size();i++){
                    Entry e=order.get(i);
                    System.out.printf(Locale.ROOT, "  %d) %s  [drive.id=%s]%n", i+1, e.label, e.driveId);
                }
            }
            if (!remaining.isEmpty()) {
                System.out.printf(Locale.ROOT, "Uncovered chunks: %,d (may be on other drives or not yet scanned into inventory).%n", remaining.size());
            }
        }

        private static long countCatalogEntries(Path cat) throws IOException { long n=0; try (BufferedReader br = Files.newBufferedReader(cat)) { while (br.readLine()!=null) n++; } return n; }
        private static int nextPow2(int x){ int r=1; while (r<x && r>0) r<<=1; return (r>0)? r : x; }

        private static Entry readEntry(Path p) throws IOException {
            try (DataInputStream din = new DataInputStream(new BufferedInputStream(Files.newInputStream(p)))) {
                byte[] mg = new byte[5]; din.readFully(mg);
                if (!Arrays.equals(mg, MAGIC)) throw new IOException("Bad inventory magic in "+p);
                String repoId = din.readUTF();
                String repoName = din.readUTF();
                String driveId = din.readUTF();
                String label = din.readUTF();
                long ts = din.readLong();
                long n = din.readLong();
                int mBits = din.readInt();
                int k = din.readInt();
                int blen = din.readInt();
                byte[] bits = new byte[blen];
                din.readFully(bits);
                return new Entry(repoId, repoName, driveId, label, ts, n, new BloomFilter(mBits, k, bits));
            }
        }

        private static BufferedReader openManifestReaderForInventory(Path manifestPath, Crypto.Ctx crypto) throws Exception {
            String fn = manifestPath.getFileName().toString();
            InputStream in = Files.newInputStream(manifestPath);
            if (fn.endsWith(".jsonl.gcm")) {
                if (crypto==null || crypto.master==null) throw new IOException("Encrypted manifest: provide --repo and --passphrase to decrypt.");
                in = crypto.decryptingInputStream(in, Crypto.MANIFEST_MAGIC);
            }
            return new BufferedReader(new InputStreamReader(in));
        }

        static final class Entry {
            final String repoId, repoName, driveId, label; final long timestamp, nEntries; final BloomFilter bf;
            Entry(String repoId, String repoName, String driveId, String label, long ts, long n, BloomFilter bf){
                this.repoId=repoId; this.repoName=repoName; this.driveId=driveId; this.label=label; this.timestamp=ts; this.nEntries=n; this.bf=bf;
            }
        }

        static final class BloomFilter {
            final int mBits, k; final byte[] bits;
            BloomFilter(int mBits, int k){ this.mBits=mBits; this.k=k; this.bits = new byte[(mBits+7)>>3]; }
            BloomFilter(int mBits, int k, byte[] pre){ this.mBits=mBits; this.k=k; this.bits = pre; }
            void add(byte[] key){ int[] idx = idxs(key); for (int b : idx){ bits[b>>3] |= (1<<(b&7)); } }
            boolean contains(byte[] key){ int[] idx = idxs(key); for (int b : idx){ if ((bits[b>>3] & (1<<(b&7)))==0) return false; } return true; }
            private int[] idxs(byte[] key){
                long h1 = toLong(key, 0) ^ toLong(key, 16);
                long h2 = toLong(key, 8) ^ (h1<<1 | h1>>>63);
                int[] r = new int[k];
                for (int i=0;i<k;i++){
                    long x = h1 + (long)i * h2;
                    int v = (int)((x ^ (x>>>32)) & 0x7fffffff);
                    r[i] = (mBits>0) ? (v % mBits) : 0;
                }
                return r;
            }
            private long toLong(byte[] b, int off){ long v=0; for (int i=0;i<8;i++){ v = (v<<8) | (b[(off+i)%b.length] & 0xFFL); } return v; }
        }
    }

    // ================= FastCDC =================

    static final class FastCDCStream {
        private final int min, avg, max, avgMask;
        private int h=0, n=0;
        private static final int[] GEAR = new int[256];
        static { long seed=0x9E3779B97F4A7C15L; for(int i=0;i<256;i++){ seed^=seed<<13; seed^=seed>>>7; seed^=seed<<17; GEAR[i]=(int)seed; } }
        FastCDCStream(int min, int avg, int max){
            if (!(min<avg && avg<max)) throw new IllegalArgumentException("min<avg<max required");
            this.min=min; this.avg=avg; this.max=max; this.avgMask = maskFor(avg);
        }
        private int maskFor(int size){ int n=0; while ((1<<n)<size) n++; return ~((1<<n)-1); }
        void update(int b){ n++; h = (h<<1) + GEAR[b & 0xFF]; }
        boolean shouldCut(){ if (n<min) return false; if ((h & avgMask)==0) return true; return n>=max; }
        void resetForNextChunk(){ n=0; h=0; }
    }

    // ================= Reed–Solomon =================

    static final class ReedSolomon {
        final int K, R; final GF256 gf = new GF256(0x11D); final byte[][] gen;
        ReedSolomon(int K, int R){ if (K<=0||R<=0) throw new IllegalArgumentException("K,R>0"); this.K=K; this.R=R; this.gen = buildVandermonde(R,K); }
        private byte[][] buildVandermonde(int rows,int cols){
            byte[][] m = new byte[rows][cols];
            for (int r=0;r<rows;r++){ byte x=(byte)(r+1), p=1; for (int c=0;c<cols;c++){ m[r][c]=p; p=gf.mul(p,x); } }
            return m;
        }
        void encode(byte[][] data, byte[][] parity){
            int len = data[0].length; for (byte[] p : parity) if (p.length!=len) throw new IllegalArgumentException("len mismatch");
            for (int r=0;r<R;r++){ byte[] out = parity[r];
                for (int i=0;i<len;i++){ int acc=0; for (int k=0;k<K;k++){ acc ^= gf.mul((byte)(data[k][i] & 0xFF), gen[r][k]) & 0xFF; } out[i]=(byte)acc; }
            }
        }
        byte[] decodeSingle(byte[][] data, List<byte[]> parity, int missingIndex){
            int len = data[0].length; for (byte[] d: data) if (d.length!=len) return null;
            int R = parity.size(); byte[][] synd = new byte[R][len];
            for (int r=0;r<R;r++){
                for (int i=0;i<len;i++){
                    int acc = parity.get(r)[i] & 0xFF;
                    for (int k=0;k<K;k++){ acc ^= gf.mul(data[k][i], gen[r][k]) & 0xFF; }
                    synd[r][i]=(byte)acc;
                }
            }
            byte[] rec = new byte[len];
            for (int i=0;i<len;i++){
                int val=0, cnt=0;
                for (int r=0;r<R;r++){
                    byte s=synd[r][i];
                    byte g=gen[r][missingIndex];
                    if (g!=0){ byte dm = gf.div(s,g); val ^= dm & 0xFF; cnt++; }
                }
                if (cnt==0) return null;
                rec[i]=(byte)val;
            }
            return rec;
        }
    }
    static final class GF256 {
        final int[] exp=new int[512], log=new int[256];
        GF256(int prim){ int x=1; for (int i=0;i<255;i++){ exp[i]=x; log[x]=i; x<<=1; if ((x&0x100)!=0) x^=prim; } for (int i=255;i<512;i++) exp[i]=exp[i-255]; log[0]=0; }
        byte mul(byte a, byte b){ int ai=a&0xFF, bi=b&0xFF; if (ai==0||bi==0) return 0; return (byte)exp[log[ai]+log[bi]]; }
        byte div(byte a, byte b){ int ai=a&0xFF, bi=b&0xFF; if (ai==0) return 0; if (bi==0) throw new ArithmeticException("/0"); return (byte)exp[(log[ai]-log[bi]+255)%255]; }
    }

    // ================= Location-aware Global Index =================

    static final class GlobalIndex implements Closeable {
        private final Path base, meta, dat, delta;
        private String repoId, repoName;

        private final Map<Integer,String> ordToDriveId = new HashMap<>();
        private final Map<Integer,String> ordToLabel   = new HashMap<>();
        private final Map<String,Integer> driveIdToOrd = new HashMap<>();
        private int currentDriveOrd = -1;

        private final Map<String,Integer> deltaMap = new HashMap<>();
        private RandomAccessFile datRaf = null;

        static GlobalIndex open(Path path, String expectedRepoIdOrNull, String expectedNameOrNull,
                                String currentDriveIdOrNull, String currentDriveLabelOrNull) throws IOException {
            Path base = path;
            if (Files.isDirectory(base)) base = base.resolve("chunks.idx");
            Path meta = Path.of(base.toString()+".meta");
            Path dat  = Path.of(base.toString()+".dat");
            Path delta= Path.of(base.toString()+".delta");

            GlobalIndex gi = new GlobalIndex(base, meta, dat, delta);
            gi.loadOrInitMeta(expectedRepoIdOrNull, expectedNameOrNull);
            gi.ensureFiles();
            gi.loadDelta();
            gi.openDat();

            if (currentDriveIdOrNull != null) {
                gi.ensureDriveOrdinal(currentDriveIdOrNull, currentDriveLabelOrNull==null? "" : currentDriveLabelOrNull);
            }
            return gi;
        }

        private GlobalIndex(Path base, Path meta, Path dat, Path delta){ this.base=base; this.meta=meta; this.dat=dat; this.delta=delta; }

        private void loadOrInitMeta(String expectedRepoIdOrNull, String expectedNameOrNull) throws IOException {
            Properties p = new Properties();
            if (Files.exists(meta)) {
                try (InputStream in = Files.newInputStream(meta)) { p.load(in); }
                this.repoId   = p.getProperty("repo.id");
                this.repoName = p.getProperty("repo.name");
                int n = Integer.parseInt(p.getProperty("drives.count", "0"));
                for (int i=0;i<n;i++){
                    String did = p.getProperty("drive."+i+".id");
                    String lab = p.getProperty("drive."+i+".label", "");
                    if (did!=null) { ordToDriveId.put(i,did); driveIdToOrd.put(did,i); ordToLabel.put(i, lab); }
                }
                LOG.debug("Opened global index meta: repoId=%s repoName=%s drives=%d", this.repoId, this.repoName, n);
            } else {
                if (expectedRepoIdOrNull==null) throw new IOException("--global-index meta missing and no repo id provided");
                this.repoId   = expectedRepoIdOrNull;
                this.repoName = expectedNameOrNull==null? "" : expectedNameOrNull;
                storeMeta(); // empty drives
                LOG.debug("Initialized global index meta at %s", meta.toAbsolutePath());
            }
            if (expectedRepoIdOrNull!=null && !Objects.equals(expectedRepoIdOrNull, this.repoId))
                throw new IOException("Global index belongs to a different repo (repo.id mismatch).");
        }

        private void storeMeta() throws IOException {
            Properties p = new Properties();
            p.setProperty("repo.id", this.repoId==null? "" : this.repoId);
            p.setProperty("repo.name", this.repoName==null? "" : this.repoName);
            int n = ordToDriveId.size();
            p.setProperty("drives.count", String.valueOf(n));
            for (Map.Entry<Integer,String> e : ordToDriveId.entrySet()){
                int ord = e.getKey();
                p.setProperty("drive."+ord+".id", e.getValue());
                p.setProperty("drive."+ord+".label", ordToLabel.getOrDefault(ord,""));
            }
            Files.createDirectories(meta.getParent()==null? Path.of(".") : meta.getParent());
            try (OutputStream out = Files.newOutputStream(meta, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                p.store(out, "ColdStore Global Index (location-aware)");
            }
        }

        private void ensureFiles() throws IOException {
            if (!Files.exists(dat))   Files.createFile(dat);
            if (!Files.exists(delta)) Files.createFile(delta);
        }

        private void loadDelta() throws IOException {
            try (BufferedReader br = Files.newBufferedReader(delta)) {
                String s;
                while ((s=br.readLine())!=null) {
                    int t = s.indexOf('\t');
                    if (t<=0) continue;
                    String hex = s.substring(0,t).trim();
                    int ord = Integer.parseInt(s.substring(t+1).trim());
                    if (hex.length()==64) deltaMap.put(hex, ord);
                }
            }
            LOG.debug("Global index loaded delta entries: %d", deltaMap.size());
        }

        private void openDat() throws IOException { datRaf = new RandomAccessFile(dat.toFile(), "r"); }

        private void ensureDriveOrdinal(String driveId, String label) throws IOException {
            Integer ord = driveIdToOrd.get(driveId);
            if (ord == null) {
                ord = ordToDriveId.keySet().stream().mapToInt(i->i).max().orElse(-1) + 1;
                if (ord > 255) throw new IOException("Exceeded 256 drives in global index.");
                ordToDriveId.put(ord, driveId);
                ordToLabel.put(ord, label==null? "" : label);
                driveIdToOrd.put(driveId, ord);
                storeMeta();
                LOG.info("Registered drive in global index: ord=%d id=%s label=%s", ord, driveId, label);
            } else {
                if (label!=null && !label.isBlank() && !Objects.equals(label, ordToLabel.get(ord))) {
                    ordToLabel.put(ord, label);
                    storeMeta();
                }
            }
            currentDriveOrd = ord;
        }

        int currentDriveOrdinal(){ return currentDriveOrd; }

        boolean contains(byte[] sha) throws IOException {
            String hx = hex(sha);
            if (deltaMap.containsKey(hx)) return true;
            return binSearchLoc(sha) >= 0;
        }

        int location(byte[] sha) throws IOException {
            String hx = hex(sha);
            Integer ord = deltaMap.get(hx);
            if (ord != null) return ord;
            return binSearchLoc(sha);
        }

        void add(byte[] sha, int driveOrd) throws IOException {
            String h = hex(sha);
            if (deltaMap.containsKey(h)) return;
            try (BufferedWriter bw = Files.newBufferedWriter(delta, StandardOpenOption.APPEND)) {
                bw.write(h); bw.write('\t'); bw.write(Integer.toString(driveOrd)); bw.write('\n');
            }
            deltaMap.put(h, driveOrd);
        }

        void compact() throws IOException {
            List<Entry> newOnes = new ArrayList<>(deltaMap.size());
            for (Map.Entry<String,Integer> e : deltaMap.entrySet()) newOnes.add(new Entry(unhex(e.getKey()), e.getValue().byteValue()));
            newOnes.sort(GlobalIndex::cmpEntry);

            Path tmp = Path.of(dat.toString()+".tmp");
            try (RandomAccessFile in = new RandomAccessFile(dat.toFile(), "r");
                 FileOutputStream outs = new FileOutputStream(tmp.toFile())) {

                long nRecs = in.length() / 33L;
                byte[] rec = new byte[33];
                int i = 0;
                for (long r=0; r<nRecs; r++) {
                    in.seek(r*33L);
                    in.readFully(rec);
                    while (i < newOnes.size() && cmpBytes(newOnes.get(i).sha, rec) < 0) {
                        outs.write(newOnes.get(i).sha); outs.write(newOnes.get(i).ord);
                        i++;
                    }
                    if (i < newOnes.size() && cmpBytes(newOnes.get(i).sha, rec) == 0) i++;
                    outs.write(rec);
                }
                while (i < newOnes.size()) {
                    outs.write(newOnes.get(i).sha); outs.write(newOnes.get(i).ord);
                    i++;
                }
            }

            Files.move(tmp, dat, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            Files.writeString(delta, "");
            deltaMap.clear();
            if (datRaf != null) datRaf.close(); openDat();
            LOG.info("Global index compacted.");
        }

        private int binSearchLoc(byte[] key) throws IOException {
            long len = datRaf.length(), n = len/33L, lo=0, hi=n-1; byte[] buf=new byte[33];
            while (lo<=hi){
                long mid=(lo+hi)>>>1;
                datRaf.seek(mid*33L);
                datRaf.readFully(buf);
                int cmp=cmpBytes(key, buf);
                if (cmp==0) return buf[32] & 0xFF;
                if (cmp>0) lo=mid+1; else hi=mid-1;
            }
            return -1;
        }

        private static int cmpBytes(byte[] key, byte[] rec33){
            for (int i=0;i<32;i++){
                int ai=key[i]&0xFF, bi=rec33[i]&0xFF;
                if (ai!=bi) return ai<bi? -1 : 1;
            }
            return 0;
        }
        private static int cmpEntry(Entry a, Entry b){
            for (int i=0;i<32;i++){
                int ai=a.sha[i]&0xFF, bi=b.sha[i]&0xFF;
                if (ai!=bi) return Integer.compare(ai, bi);
            }
            return 0;
        }
        static final class Entry { final byte[] sha; final byte ord; Entry(byte[] sha, byte ord){ this.sha=sha; this.ord=ord; } }

        String driveLabel(int ord){ return ordToLabel.getOrDefault(ord, ""); }
        String driveId(int ord){ return ordToDriveId.getOrDefault(ord, ""); }

        @Override public void close() throws IOException { if (datRaf != null) datRaf.close(); }
    }

    // ================= Crypto (chunks, parity, manifests) =================

    static final class Crypto {
        static final byte[] CHUNK_MAGIC    = new byte[]{'C','S','E','1'};
        static final byte[] MANIFEST_MAGIC = new byte[]{'C','S','M','1'};
        static final byte[] KEY_MAGIC      = new byte[]{'C','S','K','1'};

        static final SecureRandom SECURE = new SecureRandom();

        static final class Ctx {
            final boolean encryptChunksParity;
            final boolean obfuscateParity;
            final boolean encryptManifest;
            final byte[] master;

            Ctx(boolean encryptChunksParity, boolean obfuscateParity, boolean encryptManifest, byte[] master){
                this.encryptChunksParity=encryptChunksParity; this.obfuscateParity=obfuscateParity; this.encryptManifest=encryptManifest; this.master=master;
            }
            boolean anyCrypto(){ return master != null; }
            boolean enabledForChunks(){ return encryptChunksParity && master!=null; }

            byte[] encryptWithMagic(byte[] plaintext, byte[] magic){
                try {
                    byte[] nonce = new byte[12]; SECURE.nextBytes(nonce);
                    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                    c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(master, "AES"), new GCMParameterSpec(128, nonce));
                    byte[] ct = c.doFinal(plaintext);
                    ByteArrayOutputStream out = new ByteArrayOutputStream(magic.length + 12 + ct.length);
                    out.write(magic); out.write(nonce); out.write(ct);
                    return out.toByteArray();
                } catch (Exception e){ throw new RuntimeException(e); }
            }
            InputStream decryptingInputStream(InputStream in, byte[] magic){
                try {
                    byte[] hdr = in.readNBytes(4);
                    if (hdr.length!=4 || hdr[0]!=magic[0]||hdr[1]!=magic[1]||hdr[2]!=magic[2]||hdr[3]!=magic[3])
                        throw new IOException("Unexpected encrypted stream (magic mismatch)");
                    byte[] nonce = in.readNBytes(12);
                    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                    c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(master, "AES"), new GCMParameterSpec(128, nonce));
                    return new javax.crypto.CipherInputStream(in, c);
                } catch (Exception e){ throw new RuntimeException("Failed to open decrypting stream", e); }
            }
            String fileIdHash(RepoProps props, String relPath){
                try {
                    byte[] data = relPath.getBytes("UTF-8");
                    if (anyCrypto() && props.obfuscateParity) return hmacHex(data);
                    return hex(sha256(data));
                } catch (Exception e){ throw new RuntimeException(e); }
            }
            String hmacHex(byte[] data){
                try {
                    Mac mac = Mac.getInstance("HmacSHA256");
                    mac.init(new SecretKeySpec(master, "HmacSHA256"));
                    return hex(mac.doFinal(data));
                } catch (Exception e){ throw new RuntimeException(e); }
            }
        }

        static Ctx ctxForRepo(RepoVolume v, String passphrase) throws IOException {
            boolean needKey = v.props.encrypt || v.props.obfuscateParity || v.props.encryptManifest;
            if (!needKey) return new Ctx(false, v.props.obfuscateParity, v.props.encryptManifest, null);

            if (!Files.exists(v.keyFile)) {
                if (passphrase==null) passphrase = promptPass("Create passphrase for encrypted features (wraps a random 256-bit key): ");
                createWrappedKey(v.keyFile, passphrase);
                LOG.info("Created wrapped key at %s", v.keyFile);
            }
            if (passphrase==null) passphrase = promptPass("Enter passphrase for encrypted repo features: ");
            byte[] master = unwrapKey(v.keyFile, passphrase);
            return new Ctx(v.props.encrypt, v.props.obfuscateParity, v.props.encryptManifest, master);
        }

        static String promptPass(String msg) throws IOException {
            Console c = System.console();
            if (c != null) { char[] pw = c.readPassword(msg); return pw==null? "" : new String(pw); }
            System.out.print(msg);
            BufferedReader r = new BufferedReader(new InputStreamReader(System.in));
            return r.readLine();
        }

        static void createWrappedKey(Path keyFile, String passphrase) throws IOException {
            byte[] master = new byte[32]; SECURE.nextBytes(master);
            byte[] salt   = new byte[16]; SECURE.nextBytes(salt);
            int iter = 210_000;

            byte[] kek = kdf(passphrase, salt, iter, 32);
            byte[] nonce = new byte[12]; SECURE.nextBytes(nonce);

            try {
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(kek, "AES"), new GCMParameterSpec(128, nonce));
                byte[] ct = c.doFinal(master);
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                out.write(KEY_MAGIC);
                out.write(salt);
                out.write(new byte[]{ (byte)(iter>>>24), (byte)(iter>>>16), (byte)(iter>>>8), (byte)iter });
                out.write(nonce);
                out.write(ct);
                Files.write(keyFile, out.toByteArray(), StandardOpenOption.CREATE_NEW);
            } catch (Exception e){ throw new IOException("Failed to create wrapped key", e); }
        }

        static byte[] unwrapKey(Path keyFile, String passphrase) throws IOException {
            byte[] all = Files.readAllBytes(keyFile);
            if (all.length < 4+16+4+12+32) throw new IOException("key.enc too short/corrupt");
            if (all[0]!=KEY_MAGIC[0]||all[1]!=KEY_MAGIC[1]||all[2]!=KEY_MAGIC[2]||all[3]!=KEY_MAGIC[3])
                throw new IOException("key.enc has unknown format");
            byte[] salt = Arrays.copyOfRange(all, 4, 20);
            int iter = ((all[20]&0xFF)<<24)|((all[21]&0xFF)<<16)|((all[22]&0xFF)<<8)|(all[23]&0xFF);
            byte[] nonce = Arrays.copyOfRange(all, 24, 36);
            byte[] ct    = Arrays.copyOfRange(all, 36, all.length);
            byte[] kek = kdf(passphrase, salt, iter, 32);
            try {
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(kek, "AES"), new GCMParameterSpec(128, nonce));
                return c.doFinal(ct);
            } catch (Exception e){ throw new IOException("Wrong passphrase or key.enc corrupt", e); }
        }

        static byte[] kdf(String pass, byte[] salt, int iter, int len){
            try {
                PBEKeySpec spec = new PBEKeySpec(pass.toCharArray(), salt, iter, len*8);
                SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                return f.generateSecret(spec).getEncoded();
            } catch (Exception e){ throw new RuntimeException(e); }
        }

        static void encryptFile(Path plain, Path enc, Ctx ctx, byte[] magic) throws IOException {
            if (ctx.master == null) throw new IOException("Encryption requested but no master key loaded.");
            byte[] nonce = new byte[12]; SECURE.nextBytes(nonce);
            try (InputStream in = Files.newInputStream(plain);
                 OutputStream rawOut = Files.newOutputStream(enc, StandardOpenOption.CREATE_NEW)) {
                rawOut.write(magic);
                rawOut.write(nonce);
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(ctx.master, "AES"), new GCMParameterSpec(128, nonce));
                try (javax.crypto.CipherOutputStream cos = new javax.crypto.CipherOutputStream(rawOut, c)) { in.transferTo(cos); }
            } catch (Exception e){ throw new IOException("Failed to encrypt file "+plain.getFileName(), e); }
        }
    }

    // ================= Utils =================

    static byte[] sha256(byte[] buf){ try { MessageDigest md=MessageDigest.getInstance("SHA-256"); return md.digest(buf); } catch (Exception e){ throw new RuntimeException(e); } }
    static String hex(byte[] b){ StringBuilder sb=new StringBuilder(b.length*2); for (byte x:b){ sb.append(Character.forDigit((x>>>4)&0xF,16)).append(Character.forDigit(x&0xF,16)); } return sb.toString(); }
    static byte[] unhex(String s){ int n=s.length(); byte[] out=new byte[n/2]; for (int i=0;i<n;i+=2) out[i/2]=(byte)((Character.digit(s.charAt(i),16)<<4)|Character.digit(s.charAt(i+1),16)); return out; }
    static String jesc(String s){ return s.replace("\\","\\\\").replace("\"","\\\""); }
    static String extractJsonValue(String json, String key){
        String p="\""+key+"\":";
        int i=json.indexOf(p); if (i<0) return "";
        int j=i+p.length();
        if (json.charAt(j)=='"'){ int k=json.indexOf('"', j+1); return json.substring(j+1,k); }
        int k=j; while (k<json.length() && "0123456789".indexOf(json.charAt(k))>=0) k++;
        return json.substring(j,k);
    }
    static String extractArray(String json, String key){
        String p="\""+key+"\":";
        int i=json.indexOf(p); if (i<0) return "";
        int j=json.indexOf('[', i); int k=json.indexOf(']', j);
        if (j<0||k<0) return "";
        return json.substring(j+1,k).trim();
    }
    static String stripQuotes(String s){ s=s.trim(); if (s.startsWith("\"")&&s.endsWith("\"")) return s.substring(1,s.length()-1); return s; }

    static byte[] gzip(byte[] in){
        try { ByteArrayOutputStream bos = new ByteArrayOutputStream(); try (GZIPOutputStream gz = new GZIPOutputStream(bos, true)) { gz.write(in); } return bos.toByteArray(); }
        catch (IOException e){ throw new RuntimeException(e); }
    }

    /** Read a stored chunk/parity file (handles CHUNK_MAGIC + optional gzip). */
    static byte[] readPayload(Path p, Crypto.Ctx crypto, boolean maybeGunzip) throws Exception {
        byte[] fileBytes = Files.readAllBytes(p);

        if (fileBytes.length>=4 && fileBytes[0]==Crypto.CHUNK_MAGIC[0] && fileBytes[1]==Crypto.CHUNK_MAGIC[1]
                && fileBytes[2]==Crypto.CHUNK_MAGIC[2] && fileBytes[3]==Crypto.CHUNK_MAGIC[3]) {
            if (crypto.master == null) throw new IOException("Encrypted data present but no passphrase provided.");
            byte[] nonce = Arrays.copyOfRange(fileBytes,4,16);
            byte[] ct    = Arrays.copyOfRange(fileBytes,16,fileBytes.length);
            byte[] dec;
            try {
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(crypto.master,"AES"), new GCMParameterSpec(128, nonce));
                dec = c.doFinal(ct);
            } catch (Exception e){ throw new IOException("Decryption failed (wrong passphrase or file corrupt).", e); }
            if (!maybeGunzip) return dec;
            if (dec.length>=2 && (dec[0]&0xFF)==0x1f && (dec[1]&0xFF)==0x8b) {
                try (GZIPInputStream gis = new GZIPInputStream(new ByteArrayInputStream(dec))) {
                    ByteArrayOutputStream out = new ByteArrayOutputStream(); gis.transferTo(out); return out.toByteArray();
                }
            }
            return dec;
        }

        if (!maybeGunzip) return fileBytes;
        if (fileBytes.length>=2 && (fileBytes[0]&0xFF)==0x1f && (fileBytes[1]&0xFF)==0x8b) {
            try (GZIPInputStream gis = new GZIPInputStream(new ByteArrayInputStream(fileBytes))) {
                ByteArrayOutputStream out = new ByteArrayOutputStream(); gis.transferTo(out); return out.toByteArray();
            }
        }
        return fileBytes;
    }
}
