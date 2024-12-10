Referer:[TwoFish Algorizm 4 python/K-Czaplicki](https://github.com/K-Czaplicki/TwoFish)

English
---
# Secure Delete Py

**Secure Delete Py** is a robust tool for securely deleting files and directories, offering significant forensic resistance. This tool is designed for those who need to ensure that their sensitive data is unrecoverable even by advanced recovery techniques.

・ The process begins by encrypting the file itself using a combination of AES and Twofish encryption algorithms. This step alone provides a level of secure deletion that exceeds the typical encryption-based deletion methods recommended for enterprises.

・The decryption key, initialization vector (IV), and the original data used in this encryption process are subjected to rigorous in-memory cleansing. Specifically, these components are overwritten with random data five times, then zeroed out twice before being deleted from memory. This ensures that no trace of these sensitive elements remains accessible.

・Following this comprehensive encryption and cleansing routine, the file undergoes an additional overwrite using the Gutmann method. The Gutmann method involves a series of 35 write passes, which further enhances the security of the deletion process.

・To further optimize the process for SSDs and meet medium-level data erasure standards used by state-level entities, the file is overwritten with a sequence of random data followed by zeros (Random-Random-Zero). This method is particularly effective for SSDs, where traditional overwriting techniques may fall short due to how data is stored and managed at the hardware level.

・To prevent any chance of recovery based on the file name, the tool proceeds to rename the file randomly 35 times. This step is particularly critical in scenarios where the content might be inferred or reconstructed from the file name itself.

・Secure Delete Py thus combines encryption with multiple overwrite processes to provide a deletion mechanism that is suitable even for medium-grade state-level data erasure standards, ensuring that your data remains permanently deleted and irrecoverable.
---
日本語
---

# Secure Delete Py

**Secure Delete Py** は、ファイルやディレクトリを安全に削除するための強力なツールであり、フォレンジックに対して非常に高い抵抗力を持っています。このツールは、機密性の高いデータを高度な復旧技術から安全に保護し、回復不可能にする必要がある方に最適です。

・ プロセスは、ファイル自体をAESとTwofishの暗号化アルゴリズムを組み合わせて暗号化することから始まります。このステップだけでも、企業向けに推奨される典型的な暗号化消去方法を同レベルのセキュアな削除を提供します。

・ この暗号化プロセスで使用される復号鍵、初期化ベクトル（IV）、ポインターアドレスを保存していた変数、および元のデータは、メモリ上で徹底的にクリーンアップされます。具体的には、これらの要素はランダムデータで5回上書きされ、その後2回ゼロクリアされた後、メモリから削除されます。この方法により、これらの情報の痕跡が物理的な解析を用いてもアクセス可能な状態で残ることは基本ありません。

・ この暗号化とクリーンアップのルーティンを完了した後、ファイルにはグートマン方式で追加の上書きが行われます。グートマン方式は35回の書き込みパスを含むもので、削除プロセスのセキュリティをさらに高めます。

・ さらに、SSDに最適化され、国が採用する中程度の重要度のデータ消去基準を満たすために、ランダムデータとゼロのシーケンス（ランダム-ランダム-ゼロ）でファイルを上書きします。この方法は、SSDのデータストレージと管理のハードウェアレベルにより、従来の上書き方式が通用しない場合にも特に効果的です。

・ ファイル名から内容が推測されるのを防ぐため、ツールは続けてファイルをランダムに35回名前を変更します。このステップは、特にファイル名から内容が推測・再構築される可能性があるシナリオにおいて重要です。

・ Secure Delete Pyは、暗号化と複数の上書きプロセスを組み合わせ、HDD、SSDともに最適化された方法で、中程度の国家レベルのデータ消去基準にも適合する削除メカニズムを提供し、データをほとんどの場合で永続的に削除し回復不可能にします。
