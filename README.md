# Common Vulnerability Scoring System Version 3

## Usage

Demo code (app.js) :

```javascript:app.js
var cvss3 = require('cvss3');

var vector_cve_2013_1937 = "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N";
var base = (new cvss3.BaseMetrics()).importVector(vector_cve_2013_1937);
console.log('CVE-2013-1937 : Vector : '+base.getVector());
console.log('                Score  : '+base.getScore());
```

Operation (on Windows) :

```shell
C:>npm install cvss3
cvss3@0.0.1 node_modules\cvss3

C:\home\project\cvss-demo>node app.js
CVE-2013-1937 : Vector : AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
                Score  : 6.1
```

## Reference

- [Common Vulnerability Scoring System (CVSS-SIG)](http://www.first.org/cvss)
    - [CVSS v3.0 User Guide](http://www.first.org/cvss/user-guide)
    - [CVSS v3.0 Specification Document](http://www.first.org/cvss/specification-document)
    - [CVSS v3.0 Calculator](http://www.first.org/cvss/calculator/3.0)
- [共通脆弱性評価システムCVSS v3概説：IPA 独立行政法人 情報処理推進機構](http://www.ipa.go.jp/security/vuln/CVSSv3.html)
- [CVSS に関するメモ — Baldanders.info](http://www.baldanders.info/spiegel/log2/000290.shtml)
- [CVSS に関するメモ 2 — Baldanders.info](http://www.baldanders.info/spiegel/log2/000334.shtml)
- [Demo for CVSS](http://www.baldanders.info/spiegel/archive/cvss/cvss2.html)
