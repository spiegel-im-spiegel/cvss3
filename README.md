# Common Vulnerability Scoring System Version 3

[![npm version](https://badge.fury.io/js/cvss3.svg)](http://badge.fury.io/js/cvss3)
[![Build Status](https://travis-ci.org/spiegel-im-spiegel/cvss3.svg)](https://travis-ci.org/spiegel-im-spiegel/cvss3)

## Usage

Demo code (app.js) :

```javascript:app.js
var cvss3 = require('cvss3');

var vector_cve_2013_1937 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N";
var vector_temporal_x = "E:X/RL:X/RC:X";
var vector_env_x = "CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X";
var vector_full = vector_cve_2013_1937 + "/" + vector_temporal_x + "/" + vector_env_x;
var base = new cvss3.BaseMetrics(vector_full);
var temporal = new cvss3.TemporalMetrics(vector_full);
var env = new cvss3.EnvironmentalMetrics(vector_full);
console.log('CVE-2013-1937 :');
console.log('            Vector(Base) : '+base.getVector());
console.log('            Vector(Full) : '+env.getVector(base, temporal));
console.log('             Base Score  : '+base.getScore());
console.log('         Temporal Score  : '+temporal.getScore(base));
console.log('    Environmental Score  : '+env.getScore(base, temporal));
```

Operation (on Windows) :

```shell
C:>npm install cvss3
cvss3@0.1.0 node_modules\cvss3

C:>node app.js
CVE-2013-1937 :
            Vector(Base) : CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
            Vector(Full) : CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/E:X/RL:X/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X
             Base Score  : 6.1
         Temporal Score  : 6.1
    Environmental Score  : 6.1
```

## License

These codes are licensed under CC0.

[![CC0](http://i.creativecommons.org/p/zero/1.0/88x31.png "CC0")](http://creativecommons.org/publicdomain/zero/1.0/deed.ja)

## Reference

- [Common Vulnerability Scoring System (CVSS-SIG)](http://www.first.org/cvss)
    - [CVSS v3.0 User Guide](http://www.first.org/cvss/user-guide)
    - [CVSS v3.0 Specification Document](http://www.first.org/cvss/specification-document)
    - [CVSS v3.0 Calculator](http://www.first.org/cvss/calculator/3.0)
- [共通脆弱性評価システムCVSS v3概説：IPA 独立行政法人 情報処理推進機構](http://www.ipa.go.jp/security/vuln/CVSSv3.html)
- [CVSS に関するメモ — Baldanders.info](http://www.baldanders.info/spiegel/log2/000290.shtml)
- [CVSS に関するメモ 2 — Baldanders.info](http://www.baldanders.info/spiegel/log2/000334.shtml)
- [CVSS に関するメモ 3 — Baldanders.info](http://www.baldanders.info/spiegel/log2/000864.shtml)
- [Demo for CVSS v3](http://www.baldanders.info/spiegel/archive/cvss/cvss3.html)
- [CVSSv3 用の node.js モジュールを作ってみた - Qiita](http://qiita.com/spiegel-im-spiegel/items/d6fe10d3df92b9d8556b)
- [node.js の CVSS v3 モジュールを使ってデモページを作ってみた - Qiita](http://qiita.com/spiegel-im-spiegel/items/f2db3759b957206d4521)
