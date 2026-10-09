# Secure Delete Py

Overwrite and delete files without reading their existing contents. Python's
standard library is sufficient; no crypto dependency is required.

```sh
python secure-delete.py path [path ...]
python secure-delete.py --NoDebug --benchmark path
python -m unittest discover -s tests -v
```

## Behaviour

The file is opened with write-only access, without initial truncation. There is
no read(), readinto(), mmap or encryption of its contents. AES/Twofish encryption
has been removed from the deletion path because encrypting existing contents
requires reading them into memory. TwoFish.py is retained as an unused legacy
module and is not imported by the deletion tool.

The deletion path performs 35 pattern passes, two random passes and one zero
pass, then removes the file. Overwrites use at most 64 KiB generated
blocks. Each pass covers exactly the original file length, preserves its length,
and calls flush and fsync. Random passes no longer write size-squared bytes.

Original file content is not loaded into Python-owned buffers. Generated patterns
and random bytes do use RAM. The OS may still cache file data or metadata; this
tool cannot guarantee that no copy ever exists in physical RAM, swap or dumps.
The standalone writable-buffer cleanup helper is best effort and is not needed
to read or clear the original file contents.

Ordinary overwrites cannot guarantee physical erasure on SSDs, remapped sectors,
copy-on-write filesystems, snapshots, journals or backups. The pass sequence is
not a certification of a military or government sanitization standard. Use only
on files intended for deletion. An interrupted run may leave a partially modified
file. Concurrent modification of the target is unsupported: descriptor-relative
operations and identity checks prevent common path substitutions, but do not
provide atomic deletion against an adversary modifying the tree or adding links
between checks. Use only on a tree that other processes cannot modify.

## 日本語

元のファイル内容をPythonのRAM領域へ読み込まない方式に変更しました。
ファイルは読み取り権限のない書き込み専用で開き、生成したデータを
64 KiB以下のブロックで上書きします。元データの読み込みが必要な
AES/Twofish暗号化工程は削除しました。外部Pythonパッケージは不要です。

各上書きパスは元のファイルサイズ分だけを書き込み、flushとfsyncを実行
します。ランダム上書きがサイズの二乗分を書き込んでいた不具合と、
パターン上書きでファイルサイズが増えていた不具合も修正しました。

生成するパターン・乱数にはRAMを使います。また、OSのキャッシュや
スワップまで含めてRAMに元の内容が存在しないことは保証できません。
SSD、スナップショット、バックアップ等の物理的な完全消去も、通常の
ファイル上書きでは保証できません。テストは一時ディレクトリ内で
作成したファイルだけを対象に実行します。

Original references:
[TwoFish Python implementation](https://github.com/K-Czaplicki/TwoFish) /
[Gutmann-pattern implementation](https://github.com/Naranbataar/Corrupt/blob/master/main.c)

## Target validation and failures

Deletion requires POSIX `dir_fd`, directory descriptors and `O_NOFOLLOW`
(Linux is tested). Platforms without these capabilities, including native
Windows, are refused before opening the target. The tool opens every ancestor
without following symbolic links and walks directories relative to open directory
FDs; it does not combine `os.walk` with manual recursion. Directory names may
have trailing separators. Trailing separators on a regular file are rejected
before any write-only open or overwrite; they retain their directory-only meaning. Root, final `.` or `..`, and paths containing `..`
are rejected. Use an explicit path without parent traversal.

Symbolic links (including broken, ancestor and directory links), files with
multiple hard links, and non-regular files such as FIFOs, devices and sockets
are refused. Regular files are also validated with `fstat` after a nonblocking,
write-only open. Each target file remains open for all overwrite passes.
Directory descriptors read directory entries only, not file contents.

Random renaming has been removed: it cannot guarantee filename sanitization
and path-based rename can overwrite another entry or operate on a substituted
target. Validated entries are unlinked relative to their parent directory FD.
A refusal or failure aborts that top-level target; earlier children may already
have been deleted. Remaining CLI arguments are still attempted. Any failure
(including a missing target, enumeration, overwrite, sync or removal failure)
is reported on stderr even with `--NoDebug`, and the exit status is 1. Complete
success exits with status 0. Library functions propagate exceptions.

### 日本語：対象とエラー処理

POSIXのディレクトリFDとリンクを追跡しないオープンが必要です。
対応しない環境（ネイティブWindows等）では処理を拒否します。
祖先を含むシンボリックリンク、ハードリンク数が2以上のファイル、
FIFO・デバイス・ソケットは拒否します。末尾スラッシュは使用できますが、
ルート、最後の `.` / `..`、`..` を含むパスは拒否します。
ファイル内容は読み込まず、ディレクトリの項目名だけを列挙します。

ランダムリネームは削除しました。失敗した対象は処理を中断し、残りの
引数は続行します。`--NoDebug` でもエラーはstderrに表示し、1件でも
失敗した場合は終了コード1を返します。中断前に処理済みの子ファイルは
復元されません。並行して対象を変更するプロセスがない環境で実行してください。
