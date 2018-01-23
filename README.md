# openidc-demo

OpenID ConnectのAuthorization Code Flowで認証をする場合の、IdP側のミニマム実装のデモ

仮のRPには[mod_auth_openidc](https://github.com/zmartzone/mod_auth_openidc)を組み込んだapacheを用意しています。

## 使い方

dockerおよび、docker-composeは事前にインストールしてください

### 起動

FQDNは実行時の環境にあわせて適当に読み替えてください

```
FQDN=your-host.example.com docker-compose up
```

### ブラウザでアクセス

- 認証不要ページ: `http://your-host.example.com/` → apacheのトップページ
- 認証必要ページ: `http://your-host.example.com/protected/` → phpinfoのページ

認証必要なページにアクセスすると自動的に`Alice`としてログインした状態になります。
