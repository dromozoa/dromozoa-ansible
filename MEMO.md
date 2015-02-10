# 実装メモ

## ファイアウォール

RHEL5で用いられるコマンドは

* system-config-securitylevel
* lokkit
* iptables

設定ファイルは

* `/etc/sysconfig/system-config-securitylevel`
* `/etc/sysconfig/iptables`

RHEL6で用いられるコマンドは

* system-config-firewall
* lokkit
* iptables

設定ファイルは

* `/etc/sysconfig/system-config-firewall`
* `/etc/sysconfig/iptables`

サーバ用途では、操作はサービス（TCP/UDPポート）の開閉に絞ることができるとする。

## RHEL5における操作

```
# ファイアウォールを有効化し、22,25を開ける
lokkit -quiet --enabled --port=22:tcp --port=25:tcp
# ファイアウォールを無効化する
lokkit -quiet --disabled
```

lokkitでポートの開放は可能だが、ポートの閉鎖は面倒である。lokkitだけを使いiptablesを直接使わないと仮定できるならば`-f`オプションを使うことができるが、そのように仮定することができないならば、ファイアウォールの有効化についてのみlokkitを使うことが安全である。無効化した後の有効化は危険かもしれない（既存の規則が削除され、`/etc/sysconfig/system-config-securitylevel`に残された内容だけになる）。

ファイアウォールが有効かどうかは`/etc/sysconfig/system-config-securitylevel`から判定する。また、lokkitを使っていない場合のことを考えるとiptables-saveの結果も確認する必要がある（あるポートが開放されているかどうかを調べる場合も）。

iptables-saveの出力の解析については、iptablesのソースコードを確認する。

```
iptables-save -t filter
```
