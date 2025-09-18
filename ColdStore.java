import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.nio.channels.FileChannel;


/**
 * ColdStore — incremental backup with streaming FastCDC + per-file Reed–Solomon parity,
 * designed to span multiple OFFLINE drives without a central hub. Each drive holds a
 * fully self-contained "repo root" (repo.properties, chunks, parity, manifests).
 *
 * Core guarantees:
 *  - Memory-safe: streaming chunker; bounded buffers (~maxChunk + small parity stripe).
 *  - Incremental: content-addressed chunks (SHA-256) dedupe within the current drive.
 *  - Parity: per-file stripes (K data, R parity). Stripe location is deterministic:
 *      parity/<SNAP>/<fileIdHash>/stripe-XXXX/{p_0..p_{R-1}} + sidecar.json
 *    so we never need a huge global "chunk->stripe" index.
 *  - Drive spanning: "Restore" searches across whatever repo roots you attach. If a chunk
 *    or stripe is missing, it asks you to attach another drive path and continues.
 *
 * Java 17+; no external deps.
 */
public class ColdStore {

    // ======== CLI ========

    public static void main(String[] args) throws Exception {
        Map<String,String> a = parseArgs(args);
        String cmd = a.getOrDefault("_cmd", "");
        if (cmd.isEmpty()) { usage(); return; }

        switch (cmd) {
            case "init" -> {
                Path repo = mustPath(a, "--repo");
                RepoVolume v = RepoVolume.openOrInit(repo,
                        a.getOrDefault("--name", repo.getFileName().toString()),
                        pInt(a.getOrDefault("--rs-k","8")),
                        pInt(a.getOrDefault("--rs-r","2")),
                        pInt(a.getOrDefault("--min-chunk","262144")),
                        pInt(a.getOrDefault("--avg-chunk","1048576")),
                        pInt(a.getOrDefault("--max-chunk","4194304")),
                        Boolean.parseBoolean(a.getOrDefault("--compress","false"))
                );
                System.out.println("Initialized repo drive: " + v.props.repoName + " at " + repo);
                v.showInfo();
            }
            case "info" -> {
                Path repo = mustPath(a, "--repo");
                RepoVolume v = RepoVolume.openOrInit(repo, null, 8,2,262144,1048576,4194304,false);
                v.showInfo();
            }
            case "list" -> {
                Path repo = mustPath(a, "--repo");
                RepoVolume v = RepoVolume.openOrInit(repo, null, 8,2,262144,1048576,4194304,false);
                v.listSnapshots();
            }
            case "backup" -> {
                Path repo = mustPath(a, "--repo");
                Path source = mustPath(a, "--source");
                long targetBytes = pLong(a.getOrDefault("--target-bytes", String.valueOf(Long.MAX_VALUE)));
                RepoVolume v = RepoVolume.openOrInit(repo, null, 8,2,262144,1048576,4194304,false);
                String snapName = "SNAP_" + DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH-mm-ss'Z'")
                        .withZone(ZoneOffset.UTC).format(Instant.now());
                Backup.runBackup(v, source, snapName, targetBytes);
            }
            case "restore" -> {
                // You can restore one snapshot (preferred), OR restore union of latest from each attached volume.
                Path firstRepo = mustPath(a, "--repo");
                String snapshot = a.get("--snapshot"); // optional if --union-latest
                boolean unionLatest = Boolean.parseBoolean(a.getOrDefault("--union-latest","false"));
                Path dest = mustPath(a, "--dest");

                // Start with one attached repo; we can add more interactively.
                List<RepoVolume> attached = new ArrayList<>();
                attached.add(RepoVolume.openOrInit(firstRepo, null, 8,2,262144,1048576,4194304,false));
                Restore.run(attached, snapshot, unionLatest, dest);
            }
            default -> usage();
        }
    }

    private static void usage() {
        System.out.println("""
        ColdStore — incremental backups with FastCDC + per-file Reed–Solomon parity (no deps)

        Commands:
          init    --repo <path> [--name <RepoName>] [--rs-k 8 --rs-r 2] [--min-chunk 262144 --avg-chunk 1048576 --max-chunk 4194304] [--compress false]
          info    --repo <path>
          list    --repo <path>
          backup  --repo <path> --source <path> [--target-bytes N]
          restore --repo <path> --dest <path> [--snapshot SNAP_...] [--union-latest true|false]

        Drive spanning:
          - Create the SAME repo name on multiple drives (init/backup on each).
          - Restore will search currently attached repos; if something is missing,
            it will prompt you to attach another drive and enter its --repo path.
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

    // ======== Repo volume (one physical drive holding a self-contained repo root) ========

    static final class RepoProps {
        final String repoName;
        final int rsK, rsR, cMin, cAvg, cMax;
        final boolean compress;
        RepoProps(String repoName, int rsK, int rsR, int cMin, int cAvg, int cMax, boolean compress) {
            this.repoName=repoName; this.rsK=rsK; this.rsR=rsR;
            this.cMin=cMin; this.cAvg=cAvg; this.cMax=cMax; this.compress=compress;
        }
    }

    static final class RepoVolume {
        final Path root;           // repo root on THIS drive (self-contained)
        final Path propsFile;      // repo.properties
        final Path chunksDir;      // chunks/aa/bb/<hash>
        final Path parityDir;      // parity/<SNAP>/<fileIdHash>/stripe-XXXX/...
        final Path manifestsDir;   // manifests/*.jsonl
        final Path chunkCatalog;   // volume-local: chunk-ids + sizes
        final Path snapIndex;      // volume-local: list of snapshots present
        final RepoProps props;

        static RepoVolume openOrInit(Path root, String nameOrNull, int k,int r,int cMin,int cAvg,int cMax, boolean compress) throws IOException {
            Files.createDirectories(root);
            Path propsFile = root.resolve("repo.properties");
            RepoProps props;
            if (Files.exists(propsFile)) {
                Properties p = new Properties();
                try (InputStream in = Files.newInputStream(propsFile)) { p.load(in); }
                String nm = p.getProperty("repoName");
                if (nameOrNull!=null && !nameOrNull.equals(nm))
                    System.out.println("Warning: ignoring --name; existing repo name is "+nm);
                props = new RepoProps(
                        nm,
                        Integer.parseInt(p.getProperty("rs.k","8")),
                        Integer.parseInt(p.getProperty("rs.r","2")),
                        Integer.parseInt(p.getProperty("cdc.min","262144")),
                        Integer.parseInt(p.getProperty("cdc.avg","1048576")),
                        Integer.parseInt(p.getProperty("cdc.max","4194304")),
                        Boolean.parseBoolean(p.getProperty("compress","false"))
                );
            } else {
                String nm = (nameOrNull!=null ? nameOrNull : "Repo");
                props = new RepoProps(nm,k,r,cMin,cAvg,cMax,compress);
                Properties p = new Properties();
                p.setProperty("repoName", nm);
                p.setProperty("rs.k", String.valueOf(k));
                p.setProperty("rs.r", String.valueOf(r));
                p.setProperty("cdc.min", String.valueOf(cMin));
                p.setProperty("cdc.avg", String.valueOf(cAvg));
                p.setProperty("cdc.max", String.valueOf(cMax));
                p.setProperty("compress", String.valueOf(compress));
                try (OutputStream out = Files.newOutputStream(propsFile, StandardOpenOption.CREATE_NEW)) { p.store(out, "ColdStore Repo"); }
            }
            RepoVolume v = new RepoVolume(root, propsFile, props);
            v.ensureLayout();
            return v;
        }

        private RepoVolume(Path root, Path propsFile, RepoProps props) {
            this.root=root; this.propsFile=propsFile; this.props=props;
            this.chunksDir = root.resolve("chunks");
            this.parityDir = root.resolve("parity");
            this.manifestsDir = root.resolve("manifests");
            this.chunkCatalog = root.resolve("chunk_catalog.txt");
            this.snapIndex = root.resolve("snapshots.txt");
        }

        void ensureLayout() throws IOException {
            Files.createDirectories(chunksDir);
            Files.createDirectories(parityDir);
            Files.createDirectories(manifestsDir);
            if (!Files.exists(chunkCatalog)) Files.createFile(chunkCatalog);
            if (!Files.exists(snapIndex)) Files.createFile(snapIndex);
        }

        void showInfo() throws IOException {
            System.out.println("Repo name: " + props.repoName);
            System.out.println("RS: k="+props.rsK+" r="+props.rsR);
            System.out.println("CDC: min="+props.cMin+" avg="+props.cAvg+" max="+props.cMax);
            System.out.println("Compression: "+props.compress);
            System.out.println("Root: " + root);
            System.out.println("Snapshots on this drive:");
            listSnapshots();
        }

        void listSnapshots() throws IOException {
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(manifestsDir, "*.jsonl")) {
                List<String> names = new ArrayList<>();
                for (Path p : ds) names.add(p.getFileName().toString().replace(".jsonl",""));
                Collections.sort(names);
                for (String n: names) System.out.println("  " + n);
                if (names.isEmpty()) System.out.println("  (none)");
            }
        }

        Path chunkPath(byte[] sha){
            String hex=hex(sha);
            return chunksDir.resolve(hex.substring(0,2)).resolve(hex.substring(2,4)).resolve(hex);
        }
        Path parityStripeDir(String snapshot, String fileIdHash, int stripeIndex){
            return parityDir.resolve(snapshot).resolve(fileIdHash).resolve(String.format("stripe-%08d", stripeIndex));
        }
    }

    // ======== BACKUP ========

    static final class Backup {

        static void runBackup(RepoVolume vol, Path source, String snapshotName, long targetBytes) throws Exception {
            Files.createDirectories(vol.manifestsDir);
            Path manifest = vol.manifestsDir.resolve(snapshotName + ".jsonl");
            try (BufferedWriter mw = Files.newBufferedWriter(manifest, StandardOpenOption.CREATE_NEW)) {
                Counters c = new Counters();
                long bytesWrittenThisDrive = 0;

                // walk files (BFS to bound stack)
                Deque<Path> dq = new ArrayDeque<>();
                dq.add(source);
                while (!dq.isEmpty()) {
                    Path p = dq.removeFirst();
                    if (Files.isDirectory(p) && !Files.isSymbolicLink(p)) {
                        try (DirectoryStream<Path> ds = Files.newDirectoryStream(p)) {
                            for (Path ch : ds) dq.addLast(ch);
                        }
                        continue;
                    }
                    if (!Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)) continue;

                    List<String> chunkIds = new ArrayList<>();
                    List<Integer> chunkSizes = new ArrayList<>();
                    String rel = source.toAbsolutePath().normalize().relativize(p.toAbsolutePath().normalize()).toString();

                    // streaming chunker
                    FastCDCStream cdc = new FastCDCStream(vol.props.cMin, vol.props.cAvg, vol.props.cMax);
                    try (InputStream in = Files.newInputStream(p)) {
                        ByteArrayOutputStream chunkBuf = new ByteArrayOutputStream(vol.props.cMax + 16);
                        int b;
                        while ((b=in.read())!=-1) {
                            cdc.update(b & 0xFF);
                            chunkBuf.write(b);
                            if (cdc.shouldCut()) {
                                bytesWrittenThisDrive += processChunk(vol, chunkBuf, chunkIds, chunkSizes, c);
                                cdc.resetForNextChunk();
                                if (bytesWrittenThisDrive >= targetBytes) {
                                    System.out.printf("Hit target-bytes (%,d). Stop here and continue on the next drive with the SAME repo name.%n", bytesWrittenThisDrive);
                                    break;
                                }
                            }
                        }
                        if (chunkBuf.size()>0) {
                            bytesWrittenThisDrive += processChunk(vol, chunkBuf, chunkIds, chunkSizes, c);
                        }
                    }

                    // per-file parity stripes
                    writeParityForFile(vol, snapshotName, rel, chunkIds, chunkSizes, c);

                    // record manifest line
                    mw.write("{\"path\":\""+jesc(rel)+"\",\"bytes\":"+Files.size(p)+",\"chunks\":[");
                    for (int i=0;i<chunkIds.size();i++){
                        if (i>0) mw.write(",");
                        mw.write("\""+chunkIds.get(i)+"\"");
                    }
                    mw.write("]}\n");
                    mw.flush();

                    if (bytesWrittenThisDrive >= targetBytes) break;
                }

                // index snapshot on this drive
                try (FileChannel ch = FileChannel.open(vol.snapIndex, StandardOpenOption.APPEND)) {
                    ch.write(ByteBuffer.wrap((snapshotName+"\n").getBytes()));
                    ch.force(true);
                }

                System.out.printf(Locale.ROOT,
                        "Backup complete on this drive: snapshot=%s newChunks=%d reused=%d bytesWritten=%,d%n",
                        snapshotName, c.newChunks, c.reusedChunks, c.bytesWritten);
            }
        }

        private static long processChunk(RepoVolume vol, ByteArrayOutputStream buf, List<String> chunkIds, List<Integer> chunkSizes, Counters c) throws Exception {
            byte[] raw = buf.toByteArray();
            buf.reset();
            byte[] sha = sha256(raw);
            Path dest = vol.chunkPath(sha);
            if (Files.exists(dest)) {
                c.reusedChunks++;
            } else {
                Files.createDirectories(dest.getParent());
                Path tmp = dest.resolveSibling(dest.getFileName().toString()+".tmp");
                try (OutputStream out = Files.newOutputStream(tmp, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                     BufferedOutputStream bos = new BufferedOutputStream(out);
                     OutputStream payload = vol.props.compress ? new GZIPOutputStream(bos, true) : bos) {
                    payload.write(raw);
                }
                try {
                    Files.move(tmp, dest, StandardCopyOption.ATOMIC_MOVE);
                } catch (FileAlreadyExistsException e) { Files.deleteIfExists(tmp); }
                try (FileChannel ch = FileChannel.open(dest, StandardOpenOption.READ)) { ch.force(true); }
                long sz = Files.size(dest);
                try (FileChannel ch = FileChannel.open(vol.chunkCatalog, StandardOpenOption.APPEND)) {
                    ch.write(ByteBuffer.wrap((hex(sha)+"\t"+sz+"\n").getBytes()));
                    ch.force(true);
                }
                c.newChunks++; c.bytesWritten+=sz;
            }
            String cid = hex(sha);
            chunkIds.add(cid);
            chunkSizes.add(raw.length); // store original size for trimming after parity decode
            return Files.size(vol.chunkPath(sha)); // count compressed size if compression enabled
        }

        private static void writeParityForFile(RepoVolume vol, String snapshot, String relPath,
                                               List<String> chunkIds, List<Integer> sizes, Counters c) throws Exception {
            int K = vol.props.rsK, R = vol.props.rsR;
            if (K<=0 || R<=0) return;
            String fileIdHash = hex(sha256(relPath.getBytes("UTF-8")));
            ReedSolomon rs = new ReedSolomon(K, R);

            // walk stripes of K data chunks
            for (int base=0, stripeIdx=0; base<chunkIds.size(); base+=K, stripeIdx++) {
                int end = Math.min(base+K, chunkIds.size());
                int kThis = end - base;
                if (kThis < K) {
                    // still make a stripe (pad zeros) so tails are recoverable
                }

                // gather data shards (decompressed)
                List<byte[]> data = new ArrayList<>();
                int maxLen = 0;
                for (int i=base;i<end;i++) {
                    String cid = chunkIds.get(i);
                    Path path = vol.chunkPath(unhex(cid));
                    byte[] raw = readMaybeGunzip(path);
                    data.add(raw);
                    maxLen = Math.max(maxLen, raw.length);
                }
                // pad to K
                while (data.size()<K) data.add(new byte[0]);

                // align shard buffers to equal length
                byte[][] dataAligned = new byte[K][maxLen];
                int[] realSizes = new int[K];
                for (int i=0;i<K;i++){
                    byte[] src = data.get(i);
                    realSizes[i] = src.length;
                    System.arraycopy(src, 0, dataAligned[i], 0, src.length);
                }

                // compute parity R shards
                byte[][] parity = new byte[R][maxLen];
                rs.encode(dataAligned, parity);

                // write parity stripe + sidecar
                Path sdir = vol.parityStripeDir(snapshot, fileIdHash, stripeIdx);
                Files.createDirectories(sdir);

                for (int pi=0; pi<R; pi++) {
                    Path pf = sdir.resolve("p_"+pi);
                    try (OutputStream os = Files.newOutputStream(pf, StandardOpenOption.CREATE_NEW)) { os.write(parity[pi]); }
                    try (FileChannel ch = FileChannel.open(pf, StandardOpenOption.READ)) { ch.force(true); }
                    c.bytesWritten += Files.size(pf);
                }

                // sidecar.json (tiny; lists the K chunk IDs for this stripe + their true sizes)
                StringBuilder sb = new StringBuilder();
                sb.append("{\"k\":").append(K).append(",\"r\":").append(R).append(",\"chunks\":[");
                for (int i=0;i<K;i++){
                    if (i>0) sb.append(',');
                    String cid = (base+i<chunkIds.size()) ? chunkIds.get(base+i) : "";
                    sb.append('"').append(cid).append('"');
                }
                sb.append("],\"sizes\":[");
                for (int i=0;i<K;i++){
                    if (i>0) sb.append(',');
                    int sizeVal = (base+i<chunkIds.size()) ? realSizes[i] : 0;
					sb.append(sizeVal);
                }
                sb.append("]}");
                Path sidecar = sdir.resolve("sidecar.json");
                try (BufferedWriter bw = Files.newBufferedWriter(sidecar, StandardOpenOption.CREATE_NEW)) {
                    bw.write(sb.toString());
                }
                try (FileChannel ch = FileChannel.open(sidecar, StandardOpenOption.READ)) { ch.force(true); }
            }
        }

        static final class Counters {
            long newChunks=0, reusedChunks=0, bytesWritten=0;
        }
    }

    // ======== RESTORE ========

    static final class Restore {

        static void run(List<RepoVolume> attached, String snapshot, boolean unionLatest, Path dest) throws Exception {
            Files.createDirectories(dest);

            if (unionLatest && snapshot != null)
                throw new IllegalArgumentException("Use either --snapshot or --union-latest, not both.");

            if (snapshot != null) {
                // Restore a specific snapshot: find a repo that has its manifest, else prompt to attach.
                RepoVolume src = requireRepoWithSnapshot(attached, snapshot);
                restoreSnapshot(attached, src, snapshot, dest);
            } else if (unionLatest) {
                // Restore union of latest snapshots present on each attached repo (best-effort across drives).
                Set<String> done = new HashSet<>();
                for (;;) {
                    boolean progressed = false;
                    for (int i=0;i<attached.size();i++) {
                        String latest = latestSnapshot(attached.get(i));
                        if (latest!=null && done.add(attached.get(i).root.toString()+":"+latest)) {
                            System.out.println("Restoring from drive "+attached.get(i).root+" snapshot "+latest);
                            restoreSnapshot(attached, attached.get(i), latest, dest);
                            progressed = true;
                        }
                    }
                    if (!progressed) break;
                    // Ask to attach another drive for more "latest" snapshots?
                    if (promptYesNo("Attach another repo drive and continue union restore? [y/N] ")) {
                        RepoVolume nv = promptAttachMore(attached.get(0).props.repoName);
                        if (nv!=null) attached.add(nv);
                    } else break;
                }
                System.out.println("Union restore complete.");
            } else {
                throw new IllegalArgumentException("Provide --snapshot SNAP_... or --union-latest true");
            }
        }

        private static void restoreSnapshot(List<RepoVolume> attached, RepoVolume manifestRepo, String snapshot, Path dest) throws Exception {
            Path manifest = manifestRepo.manifestsDir.resolve(snapshot + ".jsonl");
            if (!Files.exists(manifest)) {
                // maybe on another attached drive?
                for (RepoVolume v: attached) {
                    Path m = v.manifestsDir.resolve(snapshot + ".jsonl");
                    if (Files.exists(m)) { manifestRepo = v; manifest = m; break; }
                }
                if (!Files.exists(manifest)) {
                    // ask user to attach the drive that has this manifest
                    System.out.println("Snapshot "+snapshot+" not found on attached drives.");
                    RepoVolume nv = promptAttachMore(manifestRepo.props.repoName);
                    if (nv==null) throw new FileNotFoundException("Snapshot manifest not found.");
                    attached.add(nv);
                    restoreSnapshot(attached, nv, snapshot, dest);
                    return;
                }
            }

            try (BufferedReader br = Files.newBufferedReader(manifest)) {
                String line;
                while ((line=br.readLine())!=null) {
                    // parse minimal JSON (path + chunks)
                    String rel = extractJsonValue(line, "path");
                    String chunksArr = extractArray(line, "chunks");
                    List<String> cids = chunksArr.isBlank() ? List.of() : Arrays.asList(chunksArr.split(","));
                    Path out = dest.resolve(rel);
                    Files.createDirectories(out.getParent());

                    try (OutputStream os = Files.newOutputStream(out, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                        for (int idx=0; idx<cids.size(); idx++) {
                            String cid = stripQuotes(cids.get(idx));
                            byte[] chunk = findChunkAcross(attached, cid);
                            if (chunk != null) {
                                os.write(chunk);
                                continue;
                            }
                            // Try parity reconstruction (per-file stripe)
                            byte[] repaired = recoverFromParity(attached, manifestRepo, snapshot, rel, idx, cids);
                            if (repaired != null) {
                                os.write(repaired);
                                continue;
                            }
                            // Need another drive
                            System.out.println("Missing chunk "+cid+" for "+rel+" (snapshot "+snapshot+").");
                            RepoVolume nv = promptAttachMore(manifestRepo.props.repoName);
                            if (nv==null) throw new FileNotFoundException("Unrecoverable: missing chunk "+cid);
                            attached.add(nv);
                            idx--; // retry this chunk with new drive attached
                        }
                    }
                }
            }
            System.out.println("Snapshot restore complete: " + snapshot);
        }

        private static String latestSnapshot(RepoVolume v) throws IOException {
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(v.manifestsDir, "*.jsonl")) {
                String best=null; for (Path p: ds){
                    String n=p.getFileName().toString().replace(".jsonl","");
                    if (best==null || n.compareTo(best)>0) best=n;
                }
                return best;
            }
        }

        private static RepoVolume requireRepoWithSnapshot(List<RepoVolume> attached, String snapshot) throws Exception {
            for (RepoVolume v: attached) {
                if (Files.exists(v.manifestsDir.resolve(snapshot+".jsonl"))) return v;
            }
            System.out.println("Snapshot not found on attached drives.");
            RepoVolume nv = promptAttachMore(attached.get(0).props.repoName);
            if (nv==null) throw new FileNotFoundException("Snapshot manifest not found.");
            attached.add(nv);
            return requireRepoWithSnapshot(attached, snapshot);
        }

        private static byte[] findChunkAcross(List<RepoVolume> attached, String cid) throws Exception {
            byte[] sha = unhex(cid);
            for (RepoVolume v: attached) {
                Path p = v.chunkPath(sha);
                if (Files.exists(p)) return readMaybeGunzip(p);
            }
            return null;
        }

        private static byte[] recoverFromParity(List<RepoVolume> attached, RepoVolume manifestRepo,
                                                String snapshot, String relPath, int chunkIndexInFile,
                                                List<String> cids) throws Exception {
            int K = manifestRepo.props.rsK, R = manifestRepo.props.rsR;
            if (K<=0 || R<=0) return null;
            String fileIdHash = hex(sha256(relPath.getBytes("UTF-8")));
            int stripeIdx = chunkIndexInFile / K;
            int missingIdx = chunkIndexInFile % K;
            String sidecarName = "sidecar.json";

            // find a drive that has the parity stripe directory
            Path sdir = null;
            RepoVolume sVol = null;
            for (RepoVolume v: attached) {
                Path candidate = v.parityStripeDir(snapshot, fileIdHash, stripeIdx);
                if (Files.isDirectory(candidate) && Files.exists(candidate.resolve(sidecarName))) {
                    sdir = candidate; sVol = v; break;
                }
            }
            if (sdir == null) return null;

            // read sidecar
            String sidecar = Files.readString(sdir.resolve(sidecarName));
            int k = Integer.parseInt(extractJsonValue(sidecar, "k"));
            int r = Integer.parseInt(extractJsonValue(sidecar, "r"));
            String idArr = extractArray(sidecar, "chunks");
            String szArr = extractArray(sidecar, "sizes");
            String[] ids = idArr.isBlank()? new String[0] : idArr.split(",");
            String[] szs = szArr.isBlank()? new String[0] : szArr.split(",");
            if (k != K || r != R) return null;

            // gather K data shards (from any attached volume), aligned to max size
            byte[][] data = new byte[K][];
            int maxLen=0;
            for (int i=0;i<K;i++){
                String cid = stripQuotes(ids[i]);
                if (cid.isEmpty()) { data[i] = new byte[0]; }
                else {
                    byte[] bytes = findChunkAcross(attached, cid);
                    data[i] = (bytes!=null) ? bytes : null;
                    if (bytes!=null) maxLen=Math.max(maxLen, bytes.length);
                }
            }
            for (int i=0;i<K;i++) if (data[i]==null) data[i]=new byte[0];
            byte[][] dataAligned = new byte[K][maxLen];
            for (int i=0;i<K;i++) System.arraycopy(data[i],0,dataAligned[i],0,data[i].length);

            // read parity shards from the stripe directory
            List<byte[]> parity = new ArrayList<>();
            for (int pi=0; pi<R; pi++) {
                Path pf = sdir.resolve("p_"+pi);
                if (Files.exists(pf)) parity.add(Files.readAllBytes(pf));
            }
            if (parity.size()<1) return null;
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

            // trim to true size from sidecar
            int trueSize = Integer.parseInt(stripQuotes(szs[missingIdx]));
            if (trueSize < rec.length) {
                byte[] trimmed = new byte[trueSize];
                System.arraycopy(rec, 0, trimmed, 0, trueSize);
                return trimmed;
            }
            return rec;
        }

        private static RepoVolume promptAttachMore(String repoName) throws Exception {
            System.out.print("Attach another drive for repo '"+repoName+"'. Enter its --repo path (or blank to give up): ");
            BufferedReader r = new BufferedReader(new InputStreamReader(System.in));
            String line = r.readLine();
            if (line==null || line.isBlank()) return null;
            Path p = Paths.get(line.trim()).toAbsolutePath().normalize();
            if (!Files.isDirectory(p)) { System.out.println("Not a directory."); return null; }
            RepoVolume v = RepoVolume.openOrInit(p, null,8,2,262144,1048576,4194304,false);
            if (!v.props.repoName.equals(repoName)) {
                System.out.println("Repo name mismatch: expected "+repoName+" got "+v.props.repoName);
                return null;
            }
            return v;
        }

        private static boolean promptYesNo(String msg) throws IOException {
            System.out.print(msg);
            BufferedReader r = new BufferedReader(new InputStreamReader(System.in));
            String s=r.readLine();
            return s!=null && (s.equalsIgnoreCase("y")||s.equalsIgnoreCase("yes"));
        }
    }

    // ======== FastCDC (streaming) ========

    static final class FastCDCStream {
        private final int min, avg, max;
        private final int avgMask, maxMask;
        private int h=0, n=0;
        private static final int[] GEAR = new int[256];
        static {
            long seed=0x9E3779B97F4A7C15L;
            for (int i=0;i<256;i++){ seed^=seed<<13; seed^=seed>>>7; seed^=seed<<17; GEAR[i]=(int)seed; }
        }
        FastCDCStream(int min, int avg, int max){
            if (!(min<avg && avg<max)) throw new IllegalArgumentException("min<avg<max required");
            this.min=min; this.avg=avg; this.max=max;
            this.avgMask = maskFor(avg);
            this.maxMask = maskFor(max);
        }
        private int maskFor(int size){ int n=0; while ((1<<n)<size) n++; return ~((1<<n)-1); }
        void update(int b){
            n++; h = (h<<1) + GEAR[b & 0xFF];
        }
        boolean shouldCut(){
            if (n<min) return false;
            if ((h & avgMask)==0) return true;
            return n>=max;
        }
        void resetForNextChunk(){ n=0; h=0; }
    }

    // ======== Reed–Solomon (GF(256), encode + single erasure decode) ========

    static final class ReedSolomon {
        final int K, R;
        final GF256 gf = new GF256(0x11D);
        final byte[][] gen; // R x K Vandermonde

        ReedSolomon(int K, int R){
            if (K<=0||R<=0) throw new IllegalArgumentException("K,R>0");
            this.K=K; this.R=R;
            this.gen = buildVandermonde(R,K);
        }
        private byte[][] buildVandermonde(int rows,int cols){
            byte[][] m = new byte[rows][cols];
            for (int r=0;r<rows;r++){
                byte x=(byte)(r+1), p=1;
                for (int c=0;c<cols;c++){ m[r][c]=p; p=gf.mul(p,x); }
            }
            return m;
        }
        void encode(byte[][] data, byte[][] parity){
            int len = data[0].length;
            for (byte[] p : parity) if (p.length!=len) throw new IllegalArgumentException("len mismatch");
            for (int r=0;r<R;r++){
                byte[] out = parity[r];
                for (int i=0;i<len;i++){
                    int acc=0;
                    for (int k=0;k<K;k++){
                        acc ^= gf.mul((byte)(data[k][i] & 0xFF), gen[r][k]) & 0xFF;
                    }
                    out[i]=(byte)acc;
                }
            }
        }
        byte[] decodeSingle(byte[][] data, List<byte[]> parity, int missingIndex){
            int len = data[0].length;
            for (byte[] d: data) if (d.length!=len) return null;
            // Syndromes
            byte[][] synd = new byte[R][len];
            for (int r=0;r<R;r++){
                for (int i=0;i<len;i++){
                    int acc = parity.get(r)[i] & 0xFF;
                    for (int k=0;k<K;k++){
                        acc ^= gf.mul(data[k][i], gen[r][k]) & 0xFF;
                    }
                    synd[r][i]=(byte)acc;
                }
            }
            byte[] rec = new byte[len];
            for (int i=0;i<len;i++){
                int val=0, cnt=0;
                for (int r=0;r<R;r++){
                    byte s = synd[r][i];
                    byte g = gen[r][missingIndex];
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
        GF256(int prim){
            int x=1;
            for (int i=0;i<255;i++){ exp[i]=x; log[x]=i; x<<=1; if ((x&0x100)!=0) x^=prim; }
            for (int i=255;i<512;i++) exp[i]=exp[i-255];
            log[0]=0;
        }
        byte mul(byte a, byte b){
            int ai=a&0xFF, bi=b&0xFF;
            if (ai==0||bi==0) return 0;
            return (byte)exp[log[ai]+log[bi]];
        }
        byte div(byte a, byte b){
            int ai=a&0xFF, bi=b&0xFF;
            if (ai==0) return 0;
            if (bi==0) throw new ArithmeticException("/0");
            return (byte)exp[(log[ai]-log[bi]+255)%255];
        }
    }

    // ======== small utilities ========

    static byte[] sha256(byte[] buf){
        try { MessageDigest md=MessageDigest.getInstance("SHA-256"); return md.digest(buf); }
        catch (Exception e){ throw new RuntimeException(e); }
    }
    static String hex(byte[] b){ StringBuilder sb=new StringBuilder(b.length*2); for (byte x:b){ sb.append(Character.forDigit((x>>>4)&0xF,16)).append(Character.forDigit(x&0xF,16)); } return sb.toString(); }
    static byte[] unhex(String s){ int n=s.length(); byte[] out=new byte[n/2]; for (int i=0;i<n;i+=2) out[i/2]=(byte)((Character.digit(s.charAt(i),16)<<4)|Character.digit(s.charAt(i+1),16)); return out; }
    static String jesc(String s){ return s.replace("\\","\\\\").replace("\"","\\\""); }
    static String extractJsonValue(String json, String key){
        String p="\""+key+"\":";
        int i=json.indexOf(p);
        if (i<0) return "";
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
        String inner=json.substring(j+1,k).trim();
        return inner;
    }
    static String stripQuotes(String s){ s=s.trim(); if (s.startsWith("\"")&&s.endsWith("\"")) return s.substring(1,s.length()-1); return s; }
    static byte[] readMaybeGunzip(Path p) throws Exception {
        try (InputStream in = Files.newInputStream(p);
             BufferedInputStream bin = new BufferedInputStream(in)) {
            bin.mark(4);
            int b0=bin.read(), b1=bin.read(); bin.reset();
            InputStream payload = (b0==0x1f && b1==0x8b) ? new GZIPInputStream(bin) : bin;
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            payload.transferTo(out);
            return out.toByteArray();
        }
    }
}
