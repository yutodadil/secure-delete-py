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
pass, then renames and removes the file. Overwrites use at most 64 KiB generated
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
file. Concurrent modification of the target is unsupported.

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
