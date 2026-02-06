window.BENCHMARK_DATA = {
  "lastUpdate": 1770339441475,
  "repoUrl": "https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "email": "erenari27@gmail.com",
            "name": "Eren Arı",
            "username": "ErenAri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c5f4b3f229f0a9604cc07038a9c34dbf2b2b949a",
          "message": "Merge pull request #1 from ErenAri/feat/production-readiness-gates\n\n  feat: harden production readiness with CI quality gates, tracing ho…",
          "timestamp": "2026-02-04T21:30:33+03:00",
          "tree_id": "10a06dab12d4c287798d98e0646bf39417a065e8",
          "url": "https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/commit/c5f4b3f229f0a9604cc07038a9c34dbf2b2b949a"
        },
        "date": 1770229928642,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "PolicyBenchmark/ParsePolicy",
            "value": 29631.62904833075,
            "unit": "ns/iter",
            "extra": "iterations: 24084\ncpu: 29622.10093838233 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short",
            "value": 1198.103042077799,
            "unit": "ns/iter",
            "extra": "iterations: 586770\ncpu: 1197.9742965727628 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64",
            "value": 1504.035142801886,
            "unit": "ns/iter",
            "extra": "iterations: 465330\ncpu: 1503.8471106526556 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512",
            "value": 3625.6011819206797,
            "unit": "ns/iter",
            "extra": "iterations: 193414\ncpu: 3625.277456647398 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096",
            "value": 20691.24900298366,
            "unit": "ns/iter",
            "extra": "iterations: 33851\ncpu: 20690.064193081434 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768",
            "value": 156914.32234924866,
            "unit": "ns/iter",
            "extra": "iterations: 4461\ncpu: 156901.07531943507 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144",
            "value": 1250137.8377896636,
            "unit": "ns/iter",
            "extra": "iterations: 561\ncpu: 1250103.108734402 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576",
            "value": 5118264.869999933,
            "unit": "ns/iter",
            "extra": "iterations: 100\ncpu: 5117552.429999996 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim",
            "value": 28.656393321261554,
            "unit": "ns/iter",
            "extra": "iterations: 24476480\ncpu: 28.65366605002028 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape",
            "value": 40.93730234851458,
            "unit": "ns/iter",
            "extra": "iterations: 16931001\ncpu: 40.933190010442914 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId",
            "value": 81.62197772977963,
            "unit": "ns/iter",
            "extra": "iterations: 8597221\ncpu: 81.61463477558621 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash",
            "value": 0.1553615659999963,
            "unit": "ns/iter",
            "extra": "iterations: 1000000000\ncpu: 0.15535946299999992 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying",
            "value": 0.3113482259999927,
            "unit": "ns/iter",
            "extra": "iterations: 1000000000\ncpu: 0.311337108 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort",
            "value": 26.110364003393858,
            "unit": "ns/iter",
            "extra": "iterations: 26817195\ncpu: 26.10739161944421 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong",
            "value": 33.25043562487306,
            "unit": "ns/iter",
            "extra": "iterations: 21046778\ncpu: 33.248671744435164 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev",
            "value": 1.8680268854396553,
            "unit": "ns/iter",
            "extra": "iterations: 375394270\ncpu: 1.867896137572904 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100",
            "value": 4625.631493277595,
            "unit": "ns/iter",
            "extra": "iterations: 151137\ncpu: 4632.149903731942 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512",
            "value": 32686.921379193285,
            "unit": "ns/iter",
            "extra": "iterations: 21432\ncpu: 32687.05239828377 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096",
            "value": 267340.565184131,
            "unit": "ns/iter",
            "extra": "iterations: 2608\ncpu: 267316.35774538346 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000",
            "value": 810917.4002319442,
            "unit": "ns/iter",
            "extra": "iterations: 862\ncpu: 811037.055684484 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100",
            "value": 6.031083760000087,
            "unit": "ns/iter",
            "extra": "iterations: 100000000\ncpu: 6.03028633000001 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512",
            "value": 6.691756590449568,
            "unit": "ns/iter",
            "extra": "iterations: 104704503\ncpu: 6.691043306895777 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096",
            "value": 6.637437054590849,
            "unit": "ns/iter",
            "extra": "iterations: 105333933\ncpu: 6.637219223552577 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000",
            "value": 6.59574192736824,
            "unit": "ns/iter",
            "extra": "iterations: 106078416\ncpu: 6.594761558279705 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash",
            "value": 0.15581743299999573,
            "unit": "ns/iter",
            "extra": "iterations: 1000000000\ncpu: 0.15579625699999866 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4",
            "value": 22.105722862739366,
            "unit": "ns/iter",
            "extra": "iterations: 31983451\ncpu: 22.105056705731975 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6",
            "value": 42.72976253902164,
            "unit": "ns/iter",
            "extra": "iterations: 16423330\ncpu: 42.72662377240198 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full",
            "value": 60.58180515613642,
            "unit": "ns/iter",
            "extra": "iterations: 11413816\ncpu: 60.577820774401744 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4",
            "value": 33.94790181447872,
            "unit": "ns/iter",
            "extra": "iterations: 20617052\ncpu: 33.94544016283214 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6",
            "value": 52.08325928691694,
            "unit": "ns/iter",
            "extra": "iterations: 13294589\ncpu: 52.07834285061389 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction",
            "value": 0.15526907799998924,
            "unit": "ns/iter",
            "extra": "iterations: 1000000000\ncpu: 0.1552681719999995 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction",
            "value": 0.6222385650000036,
            "unit": "ns/iter",
            "extra": "iterations: 1000000000\ncpu: 0.6222007629999986 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4",
            "value": 139.90150736280304,
            "unit": "ns/iter",
            "extra": "iterations: 5016974\ncpu: 139.88780009623403 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6",
            "value": 238.06640602201773,
            "unit": "ns/iter",
            "extra": "iterations: 2947052\ncpu: 238.05017624392093 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString",
            "value": 209.51233272396976,
            "unit": "ns/iter",
            "extra": "iterations: 3347760\ncpu: 209.49605437665784 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId",
            "value": 71.40870878238132,
            "unit": "ns/iter",
            "extra": "iterations: 9815402\ncpu: 71.40536302028184 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison",
            "value": 0.6218499559999913,
            "unit": "ns/iter",
            "extra": "iterations: 1000000000\ncpu: 0.6217958579999987 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName",
            "value": 9.210373170787287,
            "unit": "ns/iter",
            "extra": "iterations: 76278586\ncpu: 9.208930852493832 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName",
            "value": 4.207730528127148,
            "unit": "ns/iter",
            "extra": "iterations: 166704419\ncpu: 4.207357502622621 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "erenari27@gmail.com",
            "name": "Eren Arı",
            "username": "ErenAri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "99aabf9843308bd02fbaad9c586987efcf7f7c11",
          "message": "Merge pull request #2 from ErenAri/feat/docs-security-updates-20260204\n\ndocs: update security/developer docs and hardening helpers",
          "timestamp": "2026-02-04T22:31:06+03:00",
          "tree_id": "e2accbe2455e798d0bea489fa28ddc296d8b63b0",
          "url": "https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/commit/99aabf9843308bd02fbaad9c586987efcf7f7c11"
        },
        "date": 1770233559678,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "PolicyBenchmark/ParsePolicy",
            "value": 29905.593715685558,
            "unit": "ns/iter",
            "extra": "iterations: 23678\ncpu: 29899.110609004132 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short",
            "value": 1191.442776234766,
            "unit": "ns/iter",
            "extra": "iterations: 588322\ncpu: 1191.230501324105 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64",
            "value": 1516.8678606421518,
            "unit": "ns/iter",
            "extra": "iterations: 461316\ncpu: 1516.5149420353955 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512",
            "value": 3728.9969364867115,
            "unit": "ns/iter",
            "extra": "iterations: 187693\ncpu: 3728.4016186005883 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096",
            "value": 21677.178892540465,
            "unit": "ns/iter",
            "extra": "iterations: 32254\ncpu: 21675.41737458918 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768",
            "value": 164640.5872120369,
            "unit": "ns/iter",
            "extra": "iterations: 4254\ncpu: 164618.09779031502 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144",
            "value": 1311124.6985018728,
            "unit": "ns/iter",
            "extra": "iterations: 534\ncpu: 1310964.7958801491 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576",
            "value": 5230522.67164177,
            "unit": "ns/iter",
            "extra": "iterations: 134\ncpu: 5229888.888059704 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim",
            "value": 28.6163669284714,
            "unit": "ns/iter",
            "extra": "iterations: 23875280\ncpu: 28.61489088295505 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape",
            "value": 70.75837116202383,
            "unit": "ns/iter",
            "extra": "iterations: 9907824\ncpu: 70.74914330331275 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId",
            "value": 81.51340997416051,
            "unit": "ns/iter",
            "extra": "iterations: 8600203\ncpu: 81.5084111386674 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash",
            "value": 0.15547845399999005,
            "unit": "ns/iter",
            "extra": "iterations: 1000000000\ncpu: 0.15545980300000117 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying",
            "value": 0.31086965599999417,
            "unit": "ns/iter",
            "extra": "iterations: 1000000000\ncpu: 0.310848674999999 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort",
            "value": 26.11952049971379,
            "unit": "ns/iter",
            "extra": "iterations: 26804155\ncpu: 26.116527418976677 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong",
            "value": 33.24766847291849,
            "unit": "ns/iter",
            "extra": "iterations: 21043397\ncpu: 33.24588663132666 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev",
            "value": 1.865861442082903,
            "unit": "ns/iter",
            "extra": "iterations: 374945085\ncpu: 1.8657372078900587 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100",
            "value": 4766.001539564972,
            "unit": "ns/iter",
            "extra": "iterations: 146795\ncpu: 4773.070472426902 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512",
            "value": 33263.455582993694,
            "unit": "ns/iter",
            "extra": "iterations: 21028\ncpu: 33270.19402702511 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096",
            "value": 271330.475765683,
            "unit": "ns/iter",
            "extra": "iterations: 2579\ncpu: 271301.4412562577 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000",
            "value": 815548.7697756944,
            "unit": "ns/iter",
            "extra": "iterations: 847\ncpu: 815668.5737898967 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100",
            "value": 4.503563836232657,
            "unit": "ns/iter",
            "extra": "iterations: 155412304\ncpu: 4.503127950538593 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512",
            "value": 4.660003611928282,
            "unit": "ns/iter",
            "extra": "iterations: 150268764\ncpu: 4.659636030545914 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096",
            "value": 4.623929372326688,
            "unit": "ns/iter",
            "extra": "iterations: 154378015\ncpu: 4.6233671938326175 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000",
            "value": 4.4361002026630905,
            "unit": "ns/iter",
            "extra": "iterations: 157818560\ncpu: 4.435667604621412 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash",
            "value": 0.15565744799999948,
            "unit": "ns/iter",
            "extra": "iterations: 1000000000\ncpu: 0.1556405010000006 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4",
            "value": 21.93582913419677,
            "unit": "ns/iter",
            "extra": "iterations: 32020076\ncpu: 21.93460152936552 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6",
            "value": 43.07890565867412,
            "unit": "ns/iter",
            "extra": "iterations: 16283585\ncpu: 43.07685721541058 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full",
            "value": 61.25676326931652,
            "unit": "ns/iter",
            "extra": "iterations: 11456035\ncpu: 61.25318890872791 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4",
            "value": 33.987075682655195,
            "unit": "ns/iter",
            "extra": "iterations: 20579114\ncpu: 33.98401767928401 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6",
            "value": 53.05288366434304,
            "unit": "ns/iter",
            "extra": "iterations: 13087879\ncpu: 53.04840127265854 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction",
            "value": 0.15586971999999832,
            "unit": "ns/iter",
            "extra": "iterations: 1000000000\ncpu: 0.15587123200000264 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction",
            "value": 0.31126145800000415,
            "unit": "ns/iter",
            "extra": "iterations: 1000000000\ncpu: 0.3112503639999993 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4",
            "value": 140.09091995080215,
            "unit": "ns/iter",
            "extra": "iterations: 5005909\ncpu: 140.0863373665001 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6",
            "value": 235.99416644497342,
            "unit": "ns/iter",
            "extra": "iterations: 2965773\ncpu: 235.98759008191124 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString",
            "value": 213.4667935876252,
            "unit": "ns/iter",
            "extra": "iterations: 3280782\ncpu: 213.44735462459826 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId",
            "value": 74.72987744945517,
            "unit": "ns/iter",
            "extra": "iterations: 9369277\ncpu: 74.72308439594661 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison",
            "value": 0.31161824500000534,
            "unit": "ns/iter",
            "extra": "iterations: 1000000000\ncpu: 0.3116202149999978 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName",
            "value": 10.025269905667768,
            "unit": "ns/iter",
            "extra": "iterations: 69533738\ncpu: 10.024552210899413 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName",
            "value": 4.0442269176983485,
            "unit": "ns/iter",
            "extra": "iterations: 173072970\ncpu: 4.0441103541471515 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "erenari27@gmail.com",
            "name": "Eren Arı",
            "username": "ErenAri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "8a28db192578b45b6cc3ec0cfe51103b6b2559b1",
          "message": "feat: formalize security contracts and stabilize benchmark gate (#3)",
          "timestamp": "2026-02-04T22:59:39+03:00",
          "tree_id": "1e3ffd4df3ac2600be6107afb8b23df9c659a9be",
          "url": "https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/commit/8a28db192578b45b6cc3ec0cfe51103b6b2559b1"
        },
        "date": 1770235322795,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "PolicyBenchmark/ParsePolicy_mean",
            "value": 24646.841421825742,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 24643.912862889116 ns\nthreads: 1"
          },
          {
            "name": "PolicyBenchmark/ParsePolicy_median",
            "value": 24637.969875830386,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 24629.32266526757 ns\nthreads: 1"
          },
          {
            "name": "PolicyBenchmark/ParsePolicy_stddev",
            "value": 146.1348787053772,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 145.20762717113183 ns\nthreads: 1"
          },
          {
            "name": "PolicyBenchmark/ParsePolicy_cv",
            "value": 0.005929152389318699,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.005892230993471728 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_mean",
            "value": 1160.584776635896,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 1160.4939505989619 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_median",
            "value": 1154.8594168665625,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 1154.8469635510685 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_stddev",
            "value": 14.740420894374045,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 14.683229959928067 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_cv",
            "value": 0.01270085666391476,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.01265256915156659 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_mean",
            "value": 1550.6923609613502,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 1550.5781389087006 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_median",
            "value": 1545.909101715623,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 1545.7584689302084 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_stddev",
            "value": 10.33042251419414,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 10.339606051330525 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_cv",
            "value": 0.006661812990288933,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.006668226380779209 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_mean",
            "value": 4353.237299486053,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 4352.902875910365 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_median",
            "value": 4353.249561315104,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 4352.839425749653 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_stddev",
            "value": 7.216818692587374,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 7.153650003880891 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_cv",
            "value": 0.0016578050301644242,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.0016434205420640768 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_mean",
            "value": 26836.564366743365,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 26835.966266992178 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_median",
            "value": 26825.27388474217,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 26824.402402833603 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_stddev",
            "value": 34.3631410849799,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 34.744474577432506 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_cv",
            "value": 0.0012804597718016277,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.0012946981014865736 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_mean",
            "value": 207060.03982708167,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 207052.5209713025 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_median",
            "value": 206176.04488595042,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 206162.59308314903 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_stddev",
            "value": 2553.910865782293,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 2552.2444332134746 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_cv",
            "value": 0.012334156160286141,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.012326555703068285 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_mean",
            "value": 1644402.5709064305,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 1644228.942251463 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_median",
            "value": 1644433.3888888683,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 1644343.6812865546 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_stddev",
            "value": 4927.643672919222,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 5043.182612732036 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_cv",
            "value": 0.002996616376124368,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.0030672021901197925 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_mean",
            "value": 6596495.738095361,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 6595642.163690468 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_median",
            "value": 6600427.928571575,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 6600113.785714282 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_stddev",
            "value": 11060.463450796835,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 10966.586696469947 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_cv",
            "value": 0.0016767180469657028,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.0016627018907790169 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_mean",
            "value": 22.204029947062637,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 22.20242907539631 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_median",
            "value": 22.17538185169444,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 22.174060998259804 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_stddev",
            "value": 0.05247261669492272,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.05263535619520727 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_cv",
            "value": 0.002363202392539752,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.0023707025936876114 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_mean",
            "value": 50.7716363810811,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 50.76866320130702 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_median",
            "value": 50.485845564716904,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 50.481050187369554 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_stddev",
            "value": 0.6106089336269667,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.6108899970979325 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_cv",
            "value": 0.01202657580393639,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.012032816280303504 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_mean",
            "value": 70.2306324996441,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 70.22616597784891 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_median",
            "value": 70.10866972688079,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 70.10473785589265 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_stddev",
            "value": 0.34079445162508976,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.3421534138818474 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_cv",
            "value": 0.004852504377300271,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.004872164229922094 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_mean",
            "value": 0.14436995862499913,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.14435452074999944 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_median",
            "value": 0.14409587250000302,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.14408673249999993 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_stddev",
            "value": 0.0008891421367555122,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.0008785629257902939 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_cv",
            "value": 0.006158775310485877,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.006086147640030159 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_mean",
            "value": 0.3837521219965483,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.3837218482782122 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_median",
            "value": 0.384950885597499,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.3849068087694825 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_stddev",
            "value": 0.003956114422121013,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.003963017588206187 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_cv",
            "value": 0.010309035951484842,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.010327839308573474 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_mean",
            "value": 20.72706687551515,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 20.725965058218456 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_median",
            "value": 20.72623635304056,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 20.725484858800602 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_stddev",
            "value": 0.007709024717621976,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.008786340337471315 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_cv",
            "value": 0.00037193032491870015,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.00042392913009313757 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_mean",
            "value": 20.722243268505995,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 20.72088442392932 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_median",
            "value": 20.71986739193765,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 20.718448225859007 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_stddev",
            "value": 0.006808753416312217,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.007233096427350591 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_cv",
            "value": 0.0003285722172106855,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.0003490727653978668 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_mean",
            "value": 1.9820012953077089,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 1.981888681403414 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_median",
            "value": 1.981358257292072,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 1.9812643410886224 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_stddev",
            "value": 0.013090664206166365,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.013088522372840979 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_cv",
            "value": 0.006604770762338992,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.006604065352233982 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_mean",
            "value": 4081.9535395297626,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 4085.6455141109377 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_median",
            "value": 4074.616342659423,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 4078.383110063627 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_stddev",
            "value": 28.451913459459604,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 28.4845792932612 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_cv",
            "value": 0.006970170822360031,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.006971867528614905 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_mean",
            "value": 29394.6161806477,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 29371.36463825758 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_median",
            "value": 29436.047141861876,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 29415.52626030164 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_stddev",
            "value": 184.89114525314352,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 183.59139112203454 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_cv",
            "value": 0.006289966302566279,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.006250693264789548 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_mean",
            "value": 239931.41812939403,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 239892.4907962023 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_median",
            "value": 240144.11044521153,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 240097.78638696618 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_stddev",
            "value": 1351.7654285078047,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 1346.4622356657458 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_cv",
            "value": 0.005633965901784496,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.005612773585354182 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_mean",
            "value": 718897.5962274953,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 718922.3436700832 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_median",
            "value": 718961.2493603197,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 719030.6841433126 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_stddev",
            "value": 2285.2753630736784,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 2310.7618193789363 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_cv",
            "value": 0.0031788607655192412,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.003214202256647841 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_mean",
            "value": 5.935946727896178,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 5.935518252571592 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_median",
            "value": 5.935787849988127,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 5.935527689104229 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_stddev",
            "value": 0.0018463202926899984,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.0017781891325139966 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_cv",
            "value": 0.0003110405765626492,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.0002995844771842101 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_mean",
            "value": 6.142874451835063,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 6.142343821986223 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_median",
            "value": 6.143516394939717,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 6.14270758206561 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_stddev",
            "value": 0.004891196546183092,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.0050902401837039455 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_cv",
            "value": 0.0007962390546207474,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.0008287130012949904 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_mean",
            "value": 5.947620708555621,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 5.947308446533719 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_median",
            "value": 5.946999303840282,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 5.946770730079086 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_stddev",
            "value": 0.0015963515113830717,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.0017357869584185101 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_cv",
            "value": 0.0002684017003785612,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.0002918609273460808 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_mean",
            "value": 5.776972754198502,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 5.776536726432999 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_median",
            "value": 5.776237184833639,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 5.77569726188133 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_stddev",
            "value": 0.002675518262896392,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.002815544904837261 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_cv",
            "value": 0.0004631349976424796,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.00048741054340631796 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_mean",
            "value": 0.1440750022499948,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.14406194562500121 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_median",
            "value": 0.14407260650000353,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.1440737504999987 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_stddev",
            "value": 0.00015580164620920838,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.00015715195483827872 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_cv",
            "value": 0.001081392634225789,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.0010908637541752445 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_mean",
            "value": 20.572019214611966,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 20.571079206235403 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_median",
            "value": 20.58318206130263,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 20.581700374289507 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_stddev",
            "value": 0.16261982727336136,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.16288052091650504 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_cv",
            "value": 0.007904903528276658,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.007917937570680954 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_mean",
            "value": 42.56037339711934,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 42.556547888764506 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_median",
            "value": 42.44837736983798,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 42.44603454330884 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_stddev",
            "value": 0.3099470114883805,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.30882671159275354 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_cv",
            "value": 0.007282525662929426,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.0072568553351642475 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_mean",
            "value": 57.81037901047204,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 57.807889623588345 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_median",
            "value": 57.72244042503876,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 57.721408907299356 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_stddev",
            "value": 0.191194778601207,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.19007155243866838 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_cv",
            "value": 0.0033072742624049066,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.003287986357507682 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_mean",
            "value": 31.420225362384333,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 31.41898147529239 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_median",
            "value": 31.169713066275133,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 31.167407935700936 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_stddev",
            "value": 0.7427811448566691,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.7433907905217627 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_cv",
            "value": 0.02364022333671457,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.023660562997764856 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_mean",
            "value": 45.88898544601568,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 45.88521332976437 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_median",
            "value": 45.73496568147657,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 45.73034342840714 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_stddev",
            "value": 0.28140861404382045,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.28227461263573583 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_cv",
            "value": 0.006132378201624718,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.006151755481817335 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_mean",
            "value": 0.14397375749999955,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.14395866287499892 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_median",
            "value": 0.14395269200001337,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.14393296799999433 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_stddev",
            "value": 0.00011338311394443018,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.0001180148516779808 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_cv",
            "value": 0.0007875262541816382,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.0008197829107405265 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_mean",
            "value": 0.28815365083635114,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.28813930095197265 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_median",
            "value": 0.28794201613730935,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.28792564678982696 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_stddev",
            "value": 0.00039042464325489477,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.00039837902391803013 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_cv",
            "value": 0.0013549182601771913,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.0013825917623935386 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_mean",
            "value": 121.1423598641366,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 121.13531721220976 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_median",
            "value": 121.0651610670006,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 121.06451939510329 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_stddev",
            "value": 0.18153708168760818,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.17793102397101707 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_cv",
            "value": 0.0014985433822752455,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.0014688616669844541 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_mean",
            "value": 206.90883912644313,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 206.89707831440336 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_median",
            "value": 206.93769575290008,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 206.921234111632 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_stddev",
            "value": 0.35870694598027947,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.36360440942611494 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_cv",
            "value": 0.001733647279133743,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.0017574168392729898 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_mean",
            "value": 207.57499371724296,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 207.55926870198104 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_median",
            "value": 207.55254280637584,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 207.53673442377968 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_stddev",
            "value": 0.16073093438658942,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.16707859974058695 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_cv",
            "value": 0.000774327058901593,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.0008049681461370087 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_mean",
            "value": 66.06190722333659,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 66.05588190793313 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_median",
            "value": 66.06071180114783,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 66.0553187828491 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_stddev",
            "value": 0.09926345096522142,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.10002787800108623 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_cv",
            "value": 0.0015025822767974263,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.0015142917649710941 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_mean",
            "value": 0.3238969395625706,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.3238772365776558 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_median",
            "value": 0.3238370827332551,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.32382859700013356 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_stddev",
            "value": 0.00014646410917769793,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.0001557154212453735 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_cv",
            "value": 0.00045219355692431264,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.0004807853212865046 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_mean",
            "value": 7.613693543751624,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 7.613128461239155 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_median",
            "value": 7.611163764892755,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 7.610770719578784 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_stddev",
            "value": 0.00802979510194438,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.007937832326455929 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_cv",
            "value": 0.0010546517345098874,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.0010426505170469597 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_mean",
            "value": 2.879588795663915,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 2.879380575101721 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_median",
            "value": 2.879011035041739,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 2.878875285316982 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_stddev",
            "value": 0.004764388775885763,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.004693571074769276 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_cv",
            "value": 0.0016545378920281885,
            "unit": "ns/iter",
            "extra": "iterations: 8\ncpu: 0.0016300627695258604 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "erenari27@gmail.com",
            "name": "Eren Arı",
            "username": "ErenAri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "17b202ac6557986f6af306bb70799f11ffe789cd",
          "message": "chore: add maturity program and stabilize protected-check CI (#4)\n\n* chore: add maturity program and stabilize protected-check CI\n\n* fix: harden cgroup path cache iteration for fuzz stability\n\n* fix: keep required check names branch-protection compatible",
          "timestamp": "2026-02-05T00:23:58+03:00",
          "tree_id": "a2ce3495c4c3f82371ee35c233b1937ee494b78c",
          "url": "https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/commit/17b202ac6557986f6af306bb70799f11ffe789cd"
        },
        "date": 1770240601718,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "PolicyBenchmark/ParsePolicy_mean",
            "value": 29685.13409329687,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 29682.048462562165 ns\nthreads: 1"
          },
          {
            "name": "PolicyBenchmark/ParsePolicy_median",
            "value": 29658.139609161808,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 29653.83488127758 ns\nthreads: 1"
          },
          {
            "name": "PolicyBenchmark/ParsePolicy_stddev",
            "value": 194.48792635825097,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 194.58087125098908 ns\nthreads: 1"
          },
          {
            "name": "PolicyBenchmark/ParsePolicy_cv",
            "value": 0.006551694385041293,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.006555506824147029 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_mean",
            "value": 1208.4423544730464,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1208.361701028197 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_median",
            "value": 1208.323630864588,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1208.257018837812 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_stddev",
            "value": 0.9901582905590719,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.993832565323643 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_cv",
            "value": 0.0008193674169843546,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0008224628143030263 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_mean",
            "value": 1531.043344881542,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1530.9843600811162 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_median",
            "value": 1530.75036681291,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1530.6714308552139 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_stddev",
            "value": 0.7465864628146984,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.7429116943772575 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_cv",
            "value": 0.0004876324797143234,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0004852510017397537 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_mean",
            "value": 3749.687431699894,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 3749.5214395530206 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_median",
            "value": 3748.9554388351658,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 3748.8065203882506 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_stddev",
            "value": 3.3351307368871557,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 3.3807055648823012 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_cv",
            "value": 0.0008894423328973845,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0009016365473257073 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_mean",
            "value": 21674.157034618653,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 21672.97824730247 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_median",
            "value": 21673.898341276345,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 21672.75068081944 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_stddev",
            "value": 8.532117405714555,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 8.537445806175295 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_cv",
            "value": 0.00039365394428428227,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0003939212095706278 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_mean",
            "value": 164834.52970025165,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 164826.97487052702 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_median",
            "value": 164602.6255885131,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 164593.70409604427 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_stddev",
            "value": 861.8582179662423,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 863.057952504179 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_cv",
            "value": 0.005228626669020832,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.005236145073839511 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_mean",
            "value": 1308210.0541044693,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1308119.4884950246 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_median",
            "value": 1307597.4123134797,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1307505.1110074583 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_stddev",
            "value": 1897.6703541061252,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1895.890359244303 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_cv",
            "value": 0.0014505853613892066,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00144932506236529 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_mean",
            "value": 5228992.85012434,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 5228665.4060945315 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_median",
            "value": 5228499.0261192275,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 5228248.64925377 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_stddev",
            "value": 4951.202539902926,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4911.258775924532 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_cv",
            "value": 0.0009468749875581093,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0009392949050057726 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_mean",
            "value": 28.607311389678586,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 28.605814421465837 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_median",
            "value": 28.601299784391458,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 28.599750663377677 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_stddev",
            "value": 0.015504953232953077,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.01505210040001379 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_cv",
            "value": 0.0005419926752902479,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0005261902415446937 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_mean",
            "value": 68.33276875260275,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 68.32867167823868 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_median",
            "value": 68.30900132971028,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 68.30483793648288 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_stddev",
            "value": 0.1100795816734285,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.11027994589683023 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_cv",
            "value": 0.0016109340172058466,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0016139629702760956 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_mean",
            "value": 81.81961955088268,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 81.81366725892211 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_median",
            "value": 81.81461109337035,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 81.81225598946395 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_stddev",
            "value": 0.041482655250022156,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.04170748855867362 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_cv",
            "value": 0.0005070013216600765,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0005097863224573307 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_mean",
            "value": 0.15774755925000267,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.1577358724166669 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_median",
            "value": 0.15792377549996672,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15791839949999797 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_stddev",
            "value": 0.0022653873539470273,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0022651948749641687 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_cv",
            "value": 0.0143608393354396,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.014360683085332341 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_mean",
            "value": 0.32251266308333487,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.3224904115833311 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_median",
            "value": 0.3229269174999842,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.32289585249999675 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_stddev",
            "value": 0.005910664008946783,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.005904149587910585 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_cv",
            "value": 0.018326920724410473,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.018307984906971286 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_mean",
            "value": 26.101747011733448,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 26.100346893172077 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_median",
            "value": 26.099165585975303,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 26.097520005628493 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_stddev",
            "value": 0.009739402676527675,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00968601907206339 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_cv",
            "value": 0.0003731322149490434,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00037110690948698763 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_mean",
            "value": 33.32991652367797,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 33.328600617320674 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_median",
            "value": 33.259514656857334,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 33.258114569190155 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_stddev",
            "value": 0.20876203778664662,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.20907892420291632 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_cv",
            "value": 0.0062635031695425815,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.006273258412603715 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_mean",
            "value": 1.4011606238674643,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.4010953867837703 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_median",
            "value": 1.3984558965531662,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.3983615029526917 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_stddev",
            "value": 0.007654478242749794,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.007659780314689953 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_cv",
            "value": 0.005462955575801159,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.005466994172518877 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_mean",
            "value": 4813.379022411451,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4820.037035397193 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_median",
            "value": 4816.792773474549,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4823.768445879652 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_stddev",
            "value": 29.054592081787792,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 28.59814613514898 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_cv",
            "value": 0.0060362152962622415,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0059331797505145865 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_mean",
            "value": 32914.78258218099,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 32917.998801849666 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_median",
            "value": 32913.12765752142,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 32918.01195023202 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_stddev",
            "value": 131.52852565404825,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 131.50968265391788 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_cv",
            "value": 0.003996032035929461,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.003995069185266764 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_mean",
            "value": 268406.79454079544,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 268393.8614322743 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_median",
            "value": 268300.2262039687,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 268310.0044314761 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_stddev",
            "value": 835.3618339537574,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 835.2458709161318 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_cv",
            "value": 0.0031122976427736806,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.003112015552288983 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_mean",
            "value": 804240.0179871706,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 804319.766838801 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_median",
            "value": 804169.3019514666,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 804222.1377724265 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_stddev",
            "value": 1109.515032357244,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1109.1632854027155 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_cv",
            "value": 0.0013795819749607922,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0013790078661898787 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_mean",
            "value": 4.512831395702824,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.512641585268439 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_median",
            "value": 4.503980178684472,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.5037313342543 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_stddev",
            "value": 0.02760427131968413,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.02759320187884701 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_cv",
            "value": 0.006116840825466972,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.006114645126908656 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_mean",
            "value": 4.657111973737118,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.656911925820791 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_median",
            "value": 4.657215936306802,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.657088799065783 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_stddev",
            "value": 0.001970892712054076,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.002014622696046615 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_cv",
            "value": 0.0004232006280219467,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00043260914703503517 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_mean",
            "value": 4.55220930386224,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.551990834430313 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_median",
            "value": 4.545841436301109,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.545604964781613 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_stddev",
            "value": 0.01046240660000009,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.010488200232244968 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_cv",
            "value": 0.0022983140496469373,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0023040908063598022 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_mean",
            "value": 4.4208167143591455,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.4205872345815616 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_median",
            "value": 4.420354346808135,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.420135046853959 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_stddev",
            "value": 0.0027298459905039547,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0027283586588936638 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_cv",
            "value": 0.0006174981155941637,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0006171937152489926 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_mean",
            "value": 0.16387334350000057,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.1638649972499995 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_median",
            "value": 0.1645973749999996,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.16457777399999426 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_stddev",
            "value": 0.0029743712999539406,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.002973056185142457 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_cv",
            "value": 0.018150427863540416,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.018143326732594597 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_mean",
            "value": 22.933718126590943,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 22.932819034757795 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_median",
            "value": 22.88661267059072,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 22.885587093225325 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_stddev",
            "value": 0.19402777649502692,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.19411024807204133 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_cv",
            "value": 0.008460371555280332,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.008464299473075722 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_mean",
            "value": 44.44489614849392,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 44.44312279932962 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_median",
            "value": 44.39039249374355,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 44.38983423171606 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_stddev",
            "value": 0.15871410406543293,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15885138169808752 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_cv",
            "value": 0.003571031047865575,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.003574262376101159 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_mean",
            "value": 63.04560477246897,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 63.04250490040357 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_median",
            "value": 62.955398700972694,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 62.95325269078287 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_stddev",
            "value": 0.27554082538994557,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.27466730138101975 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_cv",
            "value": 0.004370500154362385,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.004356858944849152 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_mean",
            "value": 35.77907727285701,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 35.77762960880092 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_median",
            "value": 35.79245322900369,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 35.79127705872954 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_stddev",
            "value": 0.1708205299689055,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.17068580024502963 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_cv",
            "value": 0.004774313453256512,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.004770740882259083 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_mean",
            "value": 54.12233320245775,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 54.119343453046014 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_median",
            "value": 54.13364286476946,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 54.13128633821864 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_stddev",
            "value": 0.13729356581765928,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.13816597849526394 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_cv",
            "value": 0.0025367266652026868,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.002552986966945319 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_mean",
            "value": 0.16415924708331886,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.16414712733333658 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_median",
            "value": 0.16436986949997845,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.16436336949999483 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_stddev",
            "value": 0.0022097208043894002,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.002205132438018133 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_cv",
            "value": 0.013460836618407848,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.013433877728119664 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_mean",
            "value": 0.31233268450000173,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.31231532549999724 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_median",
            "value": 0.3114643344999876,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.31143750749998844 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_stddev",
            "value": 0.002810395807082189,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.002813190957994456 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_cv",
            "value": 0.008998084243348452,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.009007534143547756 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_mean",
            "value": 140.6878291680118,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 140.68003437988224 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_median",
            "value": 140.73977048650303,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 140.7324467633741 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_stddev",
            "value": 0.3339509758841685,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.3341899373598772 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_cv",
            "value": 0.002373701960283704,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0023755320990145245 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_mean",
            "value": 237.62219095436706,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 237.60703726823297 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_median",
            "value": 237.29616733404097,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 237.28282320779513 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_stddev",
            "value": 0.8959919998718728,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.89826716613473 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_cv",
            "value": 0.003770657935074502,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0037804737454837337 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_mean",
            "value": 213.05123896741085,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 213.03697894216566 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_median",
            "value": 212.88684546824234,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 212.87703343440478 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_stddev",
            "value": 0.4916183578948122,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.4912645773826558 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_cv",
            "value": 0.0023075123161804853,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.002306006120730909 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_mean",
            "value": 74.76423549225875,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 74.75950707782114 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_median",
            "value": 74.75846040992828,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 74.75261842973957 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_stddev",
            "value": 0.03483630991974982,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.034971672209044756 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_cv",
            "value": 0.0004659488549623014,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0004677889619127757 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_mean",
            "value": 0.31651929008336316,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.31650573425001005 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_median",
            "value": 0.31676193500004507,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.3167549180000151 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_stddev",
            "value": 0.0017546602456913188,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0017639614908484082 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_cv",
            "value": 0.005543612350543266,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0055732370695535105 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_mean",
            "value": 9.181154739843265,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 9.18081574660665 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_median",
            "value": 9.178463928924645,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 9.178070034356805 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_stddev",
            "value": 0.009836794400837236,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.009826886870219272 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_cv",
            "value": 0.0010714114596226882,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0010703718647061859 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_mean",
            "value": 4.600240908499641,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.600093792450562 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_median",
            "value": 4.589522969678483,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.58943488035858 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_stddev",
            "value": 0.030804501804340495,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0308284703862638 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_cv",
            "value": 0.0066962801333783455,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.006701704742815875 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "erenari27@gmail.com",
            "name": "Eren Arı",
            "username": "ErenAri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "78fa4c413a3cbc40ce05b9e79ef34bf2b80abf72",
          "message": "feat: start phase-2 correctness gates with e2e matrix and parser fuzz (#5)",
          "timestamp": "2026-02-05T00:40:54+03:00",
          "tree_id": "ee735374978ac2002e4bb3602292e88d0a3db8a0",
          "url": "https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/commit/78fa4c413a3cbc40ce05b9e79ef34bf2b80abf72"
        },
        "date": 1770241633603,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "PolicyBenchmark/ParsePolicy_mean",
            "value": 30180.872413495144,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 30176.67403919535 ns\nthreads: 1"
          },
          {
            "name": "PolicyBenchmark/ParsePolicy_median",
            "value": 30233.66071968568,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 30232.15601105879 ns\nthreads: 1"
          },
          {
            "name": "PolicyBenchmark/ParsePolicy_stddev",
            "value": 212.04154529176904,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 212.8504949617137 ns\nthreads: 1"
          },
          {
            "name": "PolicyBenchmark/ParsePolicy_cv",
            "value": 0.007025693041164586,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.007053477619344339 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_mean",
            "value": 1208.1435637943805,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1208.0508166122395 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_median",
            "value": 1205.4768198489885,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1205.3904684564118 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_stddev",
            "value": 5.810429495662717,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 5.805713162587909 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_cv",
            "value": 0.004809386624064838,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00480585177606103 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_mean",
            "value": 1507.8339394011145,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1507.6821984315081 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_median",
            "value": 1507.7906359568417,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1507.5786288196305 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_stddev",
            "value": 1.3513845518363825,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.3463187471014677 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_cv",
            "value": 0.0008962422960005324,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0008929725034241884 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_mean",
            "value": 3627.9735859738194,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 3627.6801543673996 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_median",
            "value": 3627.7454286158722,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 3627.546611004507 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_stddev",
            "value": 1.3269756835173396,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.3721570532989167 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_cv",
            "value": 0.00036576222292455127,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0003782464260656946 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_mean",
            "value": 20728.38526991834,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 20726.76078292098 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_median",
            "value": 20723.726352551163,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 20722.591940925715 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_stddev",
            "value": 24.577921252256306,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 24.54399466478571 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_cv",
            "value": 0.0011857132590025975,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0011841693413574858 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_mean",
            "value": 157025.80430963554,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 157012.92358152082 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_median",
            "value": 157026.5136801941,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 157012.6077595884 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_stddev",
            "value": 62.56467218519905,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 62.61034230417184 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_cv",
            "value": 0.00039843561037795563,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00039875916501653233 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_mean",
            "value": 1246647.1915623231,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1246555.159958261 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_median",
            "value": 1246377.5769230847,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1246283.4991055452 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_stddev",
            "value": 615.756169636426,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 605.4310422009647 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_cv",
            "value": 0.0004939297772489649,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0004856833148251832 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_mean",
            "value": 4983580.334541025,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4982666.7397343 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_median",
            "value": 4977629.101449298,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4977201.945652136 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_stddev",
            "value": 20452.370564676978,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 18814.291403606578 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_cv",
            "value": 0.004103951214134605,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.003775948179229391 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_mean",
            "value": 28.595340541108055,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 28.593574660566258 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_median",
            "value": 28.594508197850484,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 28.592729188275083 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_stddev",
            "value": 0.007867247722155694,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.008050290996803528 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_cv",
            "value": 0.0002751234142795364,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00028154195802268067 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_mean",
            "value": 67.48050794961738,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 67.47591938455402 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_median",
            "value": 67.50011602650373,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 67.49515748619073 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_stddev",
            "value": 0.11280539333702626,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.11267440387401463 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_cv",
            "value": 0.0016716737434941888,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0016698461451391065 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_mean",
            "value": 81.62079913866175,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 81.61559738902692 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_median",
            "value": 81.84611981620371,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 81.84018796386628 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_stddev",
            "value": 0.3213197534188053,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.3215393660317399 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_cv",
            "value": 0.0039367386353683,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.003939680359124227 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_mean",
            "value": 0.1555546334166659,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15554450016666735 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_median",
            "value": 0.15555208899999684,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15554396899999998 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_stddev",
            "value": 0.00012595767493328705,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00012725688666326404 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_cv",
            "value": 0.0008097327104098471,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0008181381310615747 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_mean",
            "value": 0.310960337416669,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.3109401503333314 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_median",
            "value": 0.3109133945000054,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.3108774179999969 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_stddev",
            "value": 0.0002381432511135137,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00023325586728577933 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_cv",
            "value": 0.0007658315947683559,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0007501632292765227 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_mean",
            "value": 26.121401638197216,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 26.119651366874596 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_median",
            "value": 26.114166487857727,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 26.112843671576766 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_stddev",
            "value": 0.021171602344863344,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.02127660081770351 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_cv",
            "value": 0.000810507898393331,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00081458211362985 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_mean",
            "value": 33.28153608015013,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 33.27904032626191 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_median",
            "value": 33.277704812818385,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 33.27484669107042 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_stddev",
            "value": 0.015124237043782273,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.015641586914624615 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_cv",
            "value": 0.0004544332631570665,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00047001316027377063 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_mean",
            "value": 1.3998716567280909,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.3995875746222997 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_median",
            "value": 1.3991941942366422,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.399109591222392 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_stddev",
            "value": 0.0019750847811615007,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0015288880367571199 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_cv",
            "value": 0.0014109041865865406,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0010923846885177683 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_mean",
            "value": 4702.702063323924,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4708.117020584142 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_median",
            "value": 4688.876809760046,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4694.708365654713 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_stddev",
            "value": 43.995928770697155,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 43.686302882508606 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_cv",
            "value": 0.009355457389873497,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.009278933104574446 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_mean",
            "value": 32555.005310055687,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 32558.69888491326 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_median",
            "value": 32551.614304896048,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 32555.784573125766 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_stddev",
            "value": 96.50946274008824,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 96.26154091245719 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_cv",
            "value": 0.0029645045921795044,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.002956553677182166 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_mean",
            "value": 267838.21014757827,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 267820.62229439983 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_median",
            "value": 267895.88827339944,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 267887.6302523822 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_stddev",
            "value": 397.6703348411938,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 401.66740125404976 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_cv",
            "value": 0.0014847408613658161,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0014997627808232027 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_mean",
            "value": 799444.5576485517,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 799535.7747335676 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_median",
            "value": 799039.1546803941,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 799099.152968327 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_stddev",
            "value": 2466.6723737112047,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 2475.1623856739266 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_cv",
            "value": 0.0030854827268654603,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0030957493884482337 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_mean",
            "value": 4.498489895546742,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.498176579729255 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_median",
            "value": 4.498535175889873,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.498211545677576 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_stddev",
            "value": 0.0019071890878406036,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.001876679352141718 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_cv",
            "value": 0.00042396206996677175,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.000417208910961578 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_mean",
            "value": 4.658570915672109,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.657814001751325 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_median",
            "value": 4.652200207726768,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.6516965208461345 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_stddev",
            "value": 0.02154333696199307,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.02032912711235601 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_cv",
            "value": 0.004624451865596412,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.004364521018811037 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_mean",
            "value": 4.527865702966877,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.527474851893217 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_median",
            "value": 4.5272872388904375,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.526954541288933 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_stddev",
            "value": 0.0031721287616472086,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0032282009087121932 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_cv",
            "value": 0.0007005792507425025,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0007130245919228646 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_mean",
            "value": 4.414634104214862,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.414260213315611 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_median",
            "value": 4.415216377634793,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.4148054784258886 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_stddev",
            "value": 0.004293575113513311,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.004321520500314099 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_cv",
            "value": 0.0009725777974247127,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0009789908821591978 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_mean",
            "value": 0.1554954020833179,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15548195349999597 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_median",
            "value": 0.1555090335000102,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15548188849999178 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_stddev",
            "value": 0.0001336604040558269,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.000129971764046249 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_cv",
            "value": 0.0008595778541683739,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.000835928293416074 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_mean",
            "value": 22.625292098347533,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 22.623531661704288 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_median",
            "value": 22.41746973515944,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 22.415301909345335 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_stddev",
            "value": 0.6834939993817253,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.6833200141536077 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_cv",
            "value": 0.03020928951594155,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.03020394977987851 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_mean",
            "value": 43.06362013583865,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 43.06055625387041 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_median",
            "value": 42.97691688959725,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 42.97337155546446 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_stddev",
            "value": 0.15250852852392455,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15261740075723376 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_cv",
            "value": 0.0035414702257463727,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.003544250563263824 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_mean",
            "value": 60.77309792546851,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 60.76860802012805 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_median",
            "value": 60.75118380294531,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 60.74637585868468 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_stddev",
            "value": 0.14097307302412274,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.1418401085062674 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_cv",
            "value": 0.0023196624466472093,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0023341016542502745 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_mean",
            "value": 35.075482490027724,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 35.07231449948302 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_median",
            "value": 35.502773296598086,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 35.49977770768563 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_stddev",
            "value": 0.5616426129998536,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.561720945795762 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_cv",
            "value": 0.016012398779105427,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.01601607860251259 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_mean",
            "value": 53.502465719661814,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 53.49772782526244 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_median",
            "value": 53.48282362777627,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 53.478466218898035 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_stddev",
            "value": 0.09666198848936698,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.09615866132225694 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_cv",
            "value": 0.0018066828731940912,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.001797434493598238 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_mean",
            "value": 0.15539397108335132,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15538417524999912 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_median",
            "value": 0.15537637600002085,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.1553713619999968 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_stddev",
            "value": 0.00006416436359771321,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00006589764227882782 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_cv",
            "value": 0.00041291411211375937,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0004240949387079118 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_mean",
            "value": 0.6222613274166565,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.6222057085833346 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_median",
            "value": 0.6221736784999905,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.6221049909999864 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_stddev",
            "value": 0.00024665887610854543,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0002472395847825322 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_cv",
            "value": 0.00039639113864356614,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00039735987852869143 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_mean",
            "value": 134.73440107691872,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 134.7255893350061 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_median",
            "value": 133.95146707540303,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 133.94418843060325 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_stddev",
            "value": 1.808981556145311,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.8070536594724167 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_cv",
            "value": 0.013426278230995948,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.013412846574966775 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_mean",
            "value": 234.88779975484385,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 234.86583860971123 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_median",
            "value": 234.8578967707471,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 234.83267200220482 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_stddev",
            "value": 0.1122678104487753,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.110534393338386 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_cv",
            "value": 0.0004779635662897392,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00047062780178119796 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_mean",
            "value": 207.74960574424486,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 207.73198730011416 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_median",
            "value": 207.85124089014914,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 207.83276032697134 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_stddev",
            "value": 0.3454772752021831,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.34602554103740735 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_cv",
            "value": 0.0016629503289045525,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0016657306635087356 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_mean",
            "value": 74.89352339628363,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 74.8871234334179 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_median",
            "value": 74.81435388184073,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 74.80785194727619 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_stddev",
            "value": 0.30624049301438433,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.3060060721590692 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_cv",
            "value": 0.004089011694562371,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.004086230824864558 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_mean",
            "value": 0.3110902827500012,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.31106938858333427 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_median",
            "value": 0.31096473150000753,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.3109460179999815 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_stddev",
            "value": 0.00032756676948390845,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0003330270290337134 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_cv",
            "value": 0.0010529636817590603,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0010705875963892757 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_mean",
            "value": 9.117747704355223,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 9.11564632101493 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_median",
            "value": 9.178665542082586,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 9.178037671252579 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_stddev",
            "value": 0.09952692946576013,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.10182282740911879 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_cv",
            "value": 0.010915736286300142,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.011170116064549318 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_mean",
            "value": 4.5320143759790295,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.531720175200065 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_median",
            "value": 4.513623828055077,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.513300559066672 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_stddev",
            "value": 0.03372223829079427,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.033677601860846014 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_cv",
            "value": 0.007440893936597326,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.007431527225610134 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "erenari27@gmail.com",
            "name": "Eren Arı",
            "username": "ErenAri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "9b42d50040ced7f5667a515c0802a1d42225de8e",
          "message": "test: phase-2 failure-mode regression suite (#6)\n\n* test: add phase-2 failure-mode regression coverage\n\n* ci: make hosted benchmark alerts advisory\n\n* docs: add phase-2 correctness evidence pack contract",
          "timestamp": "2026-02-05T01:07:35+03:00",
          "tree_id": "d9173b597e1becb018aac84f8b7df978f222b9a3",
          "url": "https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/commit/9b42d50040ced7f5667a515c0802a1d42225de8e"
        },
        "date": 1770243232152,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "PolicyBenchmark/ParsePolicy_mean",
            "value": 29644.07770863942,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 29635.02784979691 ns\nthreads: 1"
          },
          {
            "name": "PolicyBenchmark/ParsePolicy_median",
            "value": 29559.952769855707,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 29553.568965517246 ns\nthreads: 1"
          },
          {
            "name": "PolicyBenchmark/ParsePolicy_stddev",
            "value": 203.6395041583592,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 195.17076068607682 ns\nthreads: 1"
          },
          {
            "name": "PolicyBenchmark/ParsePolicy_cv",
            "value": 0.006869483549458206,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.006585813304285941 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_mean",
            "value": 1203.5323491522583,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1203.4756995835492 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_median",
            "value": 1203.5328516956952,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1203.4883473097843 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_stddev",
            "value": 1.1354780004227116,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.1374532062641751 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_cv",
            "value": 0.0009434544914580131,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0009451401525247079 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_mean",
            "value": 1512.5000972621704,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1512.407041133255 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_median",
            "value": 1511.7640560057162,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1511.6090244171257 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_stddev",
            "value": 5.16449048404815,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 5.159002671191668 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_cv",
            "value": 0.0034145389434331774,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0034111205058434523 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_mean",
            "value": 3629.1454298136873,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 3628.9531675481735 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_median",
            "value": 3628.791611626555,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 3628.6538818178483 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_stddev",
            "value": 1.6610846300598208,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.6317920088579865 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_cv",
            "value": 0.00045770682442590824,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00044965915334765064 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_mean",
            "value": 20740.968792948355,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 20739.970898960823 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_median",
            "value": 20739.668258535108,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 20738.4464153294 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_stddev",
            "value": 7.560965624681732,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 7.5087541163258 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_cv",
            "value": 0.0003645425486225289,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0003620426543945646 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_mean",
            "value": 157279.19025687102,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 157271.55129933363 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_median",
            "value": 157084.76095259495,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 157079.11019995486 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_stddev",
            "value": 511.01542268039094,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 509.394230012175 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_cv",
            "value": 0.003249097492464146,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0032389470683267395 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_mean",
            "value": 1246623.3752228117,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1246562.924836598 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_median",
            "value": 1246592.7549019684,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1246538.7486631023 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_stddev",
            "value": 636.505089317742,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 645.6122972634945 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_cv",
            "value": 0.0005105833100586438,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0005179139250817385 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_mean",
            "value": 4982062.008865224,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4981833.289007104 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_median",
            "value": 4980296.7127659675,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4980047.645390072 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_stddev",
            "value": 7904.447512731037,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 7876.892968341796 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_cv",
            "value": 0.0015865815195928185,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0015811233558784318 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_mean",
            "value": 28.67987687769222,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 28.678631157087654 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_median",
            "value": 28.604239155145052,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 28.603046511311344 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_stddev",
            "value": 0.2251980944262382,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.22512814704463138 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_cv",
            "value": 0.007852129051551186,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0078500311193895 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_mean",
            "value": 68.33116010274912,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 68.32756492364977 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_median",
            "value": 68.36271520817562,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 68.35769361871338 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_stddev",
            "value": 0.26789849800832183,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.2678314156065829 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_cv",
            "value": 0.003920590512519978,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.003919815024958986 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_mean",
            "value": 81.89153290788049,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 81.88783432102107 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_median",
            "value": 81.870785209322,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 81.8691128520703 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_stddev",
            "value": 0.07604759966942214,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.07517485889618582 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_cv",
            "value": 0.0009286381261780486,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0009180223108780886 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_mean",
            "value": 0.1554772485833311,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.1554698851666648 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_median",
            "value": 0.15547621999999706,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.1554721079999979 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_stddev",
            "value": 0.00011564940485812533,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00011797126686029803 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_cv",
            "value": 0.0007438349077559135,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0007588046182309328 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_mean",
            "value": 0.31116098491666594,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.3111466840833342 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_median",
            "value": 0.31093622150000044,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.3109311125000005 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_stddev",
            "value": 0.0006057831611579928,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.000600624928700927 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_cv",
            "value": 0.0019468480642591858,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0019303594073979016 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_mean",
            "value": 26.1001462032491,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 26.09900926344861 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_median",
            "value": 26.09554943434944,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 26.094413648120703 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_stddev",
            "value": 0.013485720260125464,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.013348672269554428 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_cv",
            "value": 0.0005166913685122072,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0005114627967219086 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_mean",
            "value": 33.26492127988206,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 33.26334848406558 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_median",
            "value": 33.25721038287841,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 33.25626221470584 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_stddev",
            "value": 0.029715891744118945,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.02971178593453055 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_cv",
            "value": 0.0008933101477709043,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0008932289528447094 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_mean",
            "value": 1.5484326259191012,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.5483626496108356 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_median",
            "value": 1.5535021414567636,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.5534461584871568 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_stddev",
            "value": 0.019002357371392525,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.01899962919801577 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_cv",
            "value": 0.012271994953679899,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.01227078759797721 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_mean",
            "value": 4650.131641115223,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4654.632904403647 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_median",
            "value": 4641.882826374266,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4646.90341984534 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_stddev",
            "value": 27.63716025266237,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 25.19193115616581 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_cv",
            "value": 0.00594330706862188,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00541222727410625 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_mean",
            "value": 32612.845521241965,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 32618.77126663914 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_median",
            "value": 32586.65793765006,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 32589.794981759973 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_stddev",
            "value": 122.9704320991588,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 126.35478897896309 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_cv",
            "value": 0.0037706133927830235,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.003873683283348949 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_mean",
            "value": 268078.30227878445,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 268076.9999042302 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_median",
            "value": 268096.9881271783,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 268091.4653386264 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_stddev",
            "value": 941.0347690366617,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 939.7912313260302 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_cv",
            "value": 0.0035102981518364187,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0035056764722888128 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_mean",
            "value": 802964.525921607,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 803062.8954494327 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_median",
            "value": 803241.7062210062,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 803337.6837561359 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_stddev",
            "value": 3765.151976613773,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 3765.875748340018 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_cv",
            "value": 0.004689063906393995,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.004689390793273362 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_mean",
            "value": 4.49951856882101,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.4992976571121615 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_median",
            "value": 4.4995634556867525,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.4992275778829605 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_stddev",
            "value": 0.001961703640098747,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0019970822884384193 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_cv",
            "value": 0.0004359807855205194,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00044386534091194824 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_mean",
            "value": 4.65245534064461,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.652244158306325 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_median",
            "value": 4.652859398851182,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.652552222829926 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_stddev",
            "value": 0.0011410579317139575,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0010755416070233807 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_cv",
            "value": 0.0002452592981915353,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0002311876957496009 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_mean",
            "value": 4.573731829968238,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.572792806948721 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_median",
            "value": 4.557531961693239,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.555364344244022 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_stddev",
            "value": 0.06779673927888276,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.06789701933923667 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_cv",
            "value": 0.014823068295054278,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.01484804193097526 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_mean",
            "value": 4.423641510827728,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.423325633272387 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_median",
            "value": 4.427348490126117,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.426987459044219 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_stddev",
            "value": 0.010095947176319661,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.010126073342280542 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_cv",
            "value": 0.002282270647747531,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.002289244378960463 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_mean",
            "value": 0.1554974557500041,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15548315274999897 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_median",
            "value": 0.15546018450001498,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.1554287329999937 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_stddev",
            "value": 0.00012112891823689545,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00012052615741852509 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_cv",
            "value": 0.0007789768498311412,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0007751718130665825 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_mean",
            "value": 22.85707108725764,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 22.855626368721783 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_median",
            "value": 23.065700246720098,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 23.065029465743887 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_stddev",
            "value": 0.36050993436751994,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.36041508761126156 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_cv",
            "value": 0.015772359152721755,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.01576920631256443 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_mean",
            "value": 43.36747198344889,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 43.364011171379076 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_median",
            "value": 43.35840073030469,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 43.35463600070949 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_stddev",
            "value": 0.04662565543069175,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.04641274662464131 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_cv",
            "value": 0.0010751296605088336,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0010703056606367273 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_mean",
            "value": 61.23708480899618,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 61.233016694396355 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_median",
            "value": 61.435076755678345,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 61.42916933194727 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_stddev",
            "value": 0.48270235660609373,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.4822508192279444 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_cv",
            "value": 0.007882516911307659,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.007875666515578953 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_mean",
            "value": 34.56780056736485,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 34.565555479013895 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_median",
            "value": 34.38640498766578,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 34.38522846596381 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_stddev",
            "value": 0.452992488260751,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.4534839325987447 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_cv",
            "value": 0.013104463715531185,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.013119532618941205 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_mean",
            "value": 54.20089050931194,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 54.18771129965409 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_median",
            "value": 54.13904137588761,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 54.13478364751325 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_stddev",
            "value": 0.30935444816265345,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.317712511971813 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_cv",
            "value": 0.005707552869624993,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.005863183816989168 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_mean",
            "value": 0.15558643758333326,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15557726958333498 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_median",
            "value": 0.15553595900001937,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15552013850000893 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_stddev",
            "value": 0.00017822460888711376,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0001794487371448223 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_cv",
            "value": 0.0011455022150735686,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0011534380158838087 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_mean",
            "value": 0.6226004812500131,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.6225606159166616 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_median",
            "value": 0.622550794999995,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.6225301759999837 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_stddev",
            "value": 0.00022824239939567007,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00022079445659934879 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_cv",
            "value": 0.0003665952826400345,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0003546553555660597 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_mean",
            "value": 138.92563964435627,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 138.91723216058344 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_median",
            "value": 139.73031056027415,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 139.72719213323654 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_stddev",
            "value": 1.5287249430707106,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.528985462979011 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_cv",
            "value": 0.011003907896225502,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.011006449230226223 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_mean",
            "value": 237.03531836070965,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 237.02108888949112 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_median",
            "value": 236.44556822472225,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 236.43878148936926 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_stddev",
            "value": 2.358628636259625,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 2.3559766533610174 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_cv",
            "value": 0.00995053670723605,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.009939945278284791 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_mean",
            "value": 211.40162962705617,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 211.38690062070438 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_median",
            "value": 211.3223716847317,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 211.30301111340472 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_stddev",
            "value": 0.4381544215860523,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.43984805707759583 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_cv",
            "value": 0.0020726161021512547,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.002080772535034343 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_mean",
            "value": 74.83705864036554,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 74.83131188211655 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_median",
            "value": 74.8284029987767,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 74.82396139288562 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_stddev",
            "value": 0.02707074206198073,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.027697428000849494 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_cv",
            "value": 0.00036172910258366756,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00037013153056145626 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_mean",
            "value": 0.3117627869166597,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.3117411164166649 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_median",
            "value": 0.3112545019999687,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.31124496249998396 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_stddev",
            "value": 0.0013132221060248393,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0013186499906781572 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_cv",
            "value": 0.004212247776627328,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.004229952102037399 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_mean",
            "value": 9.185299274620794,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 9.184547504313718 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_median",
            "value": 9.183606773758388,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 9.182525675541887 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_stddev",
            "value": 0.00517033240910367,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.005222608792035496 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_cv",
            "value": 0.0005628921012284733,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.000568629950422989 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_mean",
            "value": 4.5957345429485885,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.595442712610507 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_median",
            "value": 4.592982306554698,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.592720848575326 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_stddev",
            "value": 0.007714940649009697,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.007756619880099496 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_cv",
            "value": 0.0016787176406537724,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.001687893934313292 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "erenari27@gmail.com",
            "name": "Eren Arı",
            "username": "ErenAri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "0f3f445c948072d3f133cc7f79169fc6279b23b0",
          "message": "feat: complete phases 4-7 portability, performance, and evidence gates (#7)\n\n* feat: harden phase-3 operational safety with gated SIGKILL and evidence contracts\n\n* feat: complete phases 4-7 portability perf security evidence\n\n* ci: suppress cppcheck gtest parse noise for kernel feature tests",
          "timestamp": "2026-02-05T02:17:44+03:00",
          "tree_id": "edfeb4333a4edbd4773635e00636ba1c01f7acbf",
          "url": "https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/commit/0f3f445c948072d3f133cc7f79169fc6279b23b0"
        },
        "date": 1770247433708,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "PolicyBenchmark/ParsePolicy_mean",
            "value": 24037.998146058944,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 24035.865182338483 ns\nthreads: 1"
          },
          {
            "name": "PolicyBenchmark/ParsePolicy_median",
            "value": 24028.371998730265,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 24026.61890491132 ns\nthreads: 1"
          },
          {
            "name": "PolicyBenchmark/ParsePolicy_stddev",
            "value": 134.66101710696725,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 134.49209083043397 ns\nthreads: 1"
          },
          {
            "name": "PolicyBenchmark/ParsePolicy_cv",
            "value": 0.005602006302219683,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.005595475336966797 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_mean",
            "value": 1154.914457314574,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1154.8157663635936 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_median",
            "value": 1154.5631375908495,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1154.4739904192163 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_stddev",
            "value": 1.2226900480527987,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.176731174627379 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_cv",
            "value": 0.0010586845114882513,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0010189774065284844 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_mean",
            "value": 1544.177928032261,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1544.0935265113424 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_median",
            "value": 1543.6893448842218,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1543.6442097323445 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_stddev",
            "value": 1.4665330364671352,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.4654070305630897 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_cv",
            "value": 0.0009497176522500431,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0009490403303962853 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_mean",
            "value": 4331.8076681202065,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4331.055031495168 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_median",
            "value": 4330.847638635578,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4330.3492871060525 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_stddev",
            "value": 4.0115599172741,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 2.8671269263893167 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_cv",
            "value": 0.000926070644086311,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0006619927259154513 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_mean",
            "value": 26737.43222820603,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 26735.482878805287 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_median",
            "value": 26730.810186776493,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 26728.313681677613 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_stddev",
            "value": 16.591895067152247,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 16.43466349018788 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_cv",
            "value": 0.0006205493080090546,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0006147135462145161 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_mean",
            "value": 206170.0753770077,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 206155.29852134731 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_median",
            "value": 205510.8904230347,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 205493.08078731006 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_stddev",
            "value": 1376.371705502478,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1373.3804270767425 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_cv",
            "value": 0.006675904361899322,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.006661873048751787 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_mean",
            "value": 1637639.1046057774,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1637507.6809133496 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_median",
            "value": 1637441.1463700456,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1637308.1756440352 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_stddev",
            "value": 1179.7198039820157,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1188.830639363251 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_cv",
            "value": 0.0007203783792559138,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.000726000038485413 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_mean",
            "value": 6550133.722741333,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 6549568.796729003 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_median",
            "value": 6549486.668224201,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 6548959.799065423 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_stddev",
            "value": 3629.5274265312396,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 3581.535093436627 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_cv",
            "value": 0.000554115012023331,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0005468352504710422 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_mean",
            "value": 21.894409617781374,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 21.89290195132564 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_median",
            "value": 21.888168184905506,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 21.8862346112131 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_stddev",
            "value": 0.02148000647816495,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.021093361213491698 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_cv",
            "value": 0.0009810726506514309,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0009634794537694657 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_mean",
            "value": 59.45620045615593,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 59.4522570686479 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_median",
            "value": 59.43545442417317,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 59.432210416366196 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_stddev",
            "value": 0.15681560479321785,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.1564535801991074 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_cv",
            "value": 0.002637497915946655,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00263158352454903 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_mean",
            "value": 71.69091835029265,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 71.68613064162876 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_median",
            "value": 71.65351894861448,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 71.6467910326759 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_stddev",
            "value": 0.3268671651901412,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.3267904459061908 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_cv",
            "value": 0.004559394309792753,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0045586286075317995 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_mean",
            "value": 0.14410212033332925,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.1440941282499975 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_median",
            "value": 0.14409201500001245,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.14408675549999828 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_stddev",
            "value": 0.00009699162768219358,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00009373999316988527 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_cv",
            "value": 0.00067307564564517,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0006505469328163751 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_mean",
            "value": 0.3858393146666638,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.38581539550000105 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_median",
            "value": 0.38610589300000697,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.3860685889999971 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_stddev",
            "value": 0.0017532462053430255,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0017529119091442772 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_cv",
            "value": 0.004543980197709243,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.004543395441419787 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_mean",
            "value": 20.545850516440222,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 20.5445754560899 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_median",
            "value": 20.53520057719086,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 20.53428995638361 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_stddev",
            "value": 0.021307915477396976,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.02112556514532024 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_cv",
            "value": 0.0010370909425407807,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.001028279469219118 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_mean",
            "value": 20.537941276770088,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 20.536739158766533 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_median",
            "value": 20.52766808939851,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 20.526624549848233 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_stddev",
            "value": 0.020503602138084172,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.020298355231872314 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_cv",
            "value": 0.0009983280145646949,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0009883923185150616 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_mean",
            "value": 1.142512205097784,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.142437203889009 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_median",
            "value": 1.1419925176881969,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.1418944046482005 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_stddev",
            "value": 0.004091139279705743,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.004086723985974641 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_cv",
            "value": 0.003580827637071584,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.003577197916929601 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_mean",
            "value": 4119.707240985456,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4123.001306037678 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_median",
            "value": 4121.77154151443,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4125.123697393197 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_stddev",
            "value": 14.818619474761384,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 14.690546608385715 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_cv",
            "value": 0.0035970078959340537,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0035630710538153455 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_mean",
            "value": 29241.744866671623,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 29234.375159565156 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_median",
            "value": 29247.258636374987,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 29245.086676966486 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_stddev",
            "value": 119.10055962769894,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 123.00020665852166 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_cv",
            "value": 0.004072963503742357,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.004207382780961453 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_mean",
            "value": 239174.73449067664,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 239133.88459352063 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_median",
            "value": 239265.79763919336,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 239233.6671230155 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_stddev",
            "value": 766.0053203020533,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 763.7692543152189 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_cv",
            "value": 0.0032027016646773497,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0031938980776959843 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_mean",
            "value": 716286.8936225538,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 716367.5304420333 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_median",
            "value": 714776.8214285952,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 714861.6336737098 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_stddev",
            "value": 2975.066054880171,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 2978.3464622805373 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_cv",
            "value": 0.004153455942540081,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.004157567639117806 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_mean",
            "value": 5.952035255414599,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 5.951698323445818 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_median",
            "value": 5.951919087589687,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 5.9515183794860524 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_stddev",
            "value": 0.0008633318864719521,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0008820173803814569 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_cv",
            "value": 0.00014504818090359503,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00014819591525781515 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_mean",
            "value": 6.141568312504599,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 6.141126309160069 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_median",
            "value": 6.139103771819474,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 6.138664924993715 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_stddev",
            "value": 0.0043803184270739285,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.004387998749810423 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_cv",
            "value": 0.0007132247341701533,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0007145267055108945 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_mean",
            "value": 5.951549877289067,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 5.951145686286583 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_median",
            "value": 5.950261996286231,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 5.949818985086981 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_stddev",
            "value": 0.004331353678017402,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00433264270290805 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_cv",
            "value": 0.0007277690294667135,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0007280350593486392 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_mean",
            "value": 5.777733078369792,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 5.7772943453226935 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_median",
            "value": 5.777755166607992,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 5.777363324147928 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_stddev",
            "value": 0.0007843550385787336,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0008015133126602286 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_cv",
            "value": 0.0001357548069354637,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00013873506606239218 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_mean",
            "value": 0.14415978116666395,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.1441506073333348 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_median",
            "value": 0.14408235300001593,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.14406252599998481 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_stddev",
            "value": 0.00027927802539954634,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0002810268519129209 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_cv",
            "value": 0.0019372811413793103,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0019495363711029853 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_mean",
            "value": 20.93873825687866,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 20.93730874052076 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_median",
            "value": 20.939473008240714,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 20.937965848307204 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_stddev",
            "value": 0.05638706382692709,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.05612064351115801 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_cv",
            "value": 0.0026929542332094995,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0026804134288064265 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_mean",
            "value": 42.55500624268395,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 42.55166242972796 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_median",
            "value": 42.50147796581221,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 42.498973114105254 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_stddev",
            "value": 0.2468156104654821,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.24704358498970835 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_cv",
            "value": 0.005799919498494131,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.005805732864084664 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_mean",
            "value": 57.953801918779185,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 57.949857033577985 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_median",
            "value": 57.93366018803695,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 57.93009973727865 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_stddev",
            "value": 0.06446923441297922,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0647944060055669 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_cv",
            "value": 0.0011124245912861983,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0011181115764966076 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_mean",
            "value": 31.624479098160133,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 31.62259342235043 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_median",
            "value": 31.580582277646005,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 31.579432679091358 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_stddev",
            "value": 0.1959613483916426,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.19574319980805874 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_cv",
            "value": 0.006196508337209051,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.006189979335145549 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_mean",
            "value": 44.84221082459057,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 44.84000338963389 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_median",
            "value": 44.89151288552844,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 44.888819949122656 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_stddev",
            "value": 0.1405831935624784,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.1406252807748554 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_cv",
            "value": 0.0031350638377844065,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0031361567828820714 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_mean",
            "value": 0.14408441541666167,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.14407160316667006 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_median",
            "value": 0.14405282000001307,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.14403975200001184 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_stddev",
            "value": 0.00014796253969437346,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00014833974397581869 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_cv",
            "value": 0.0010269156401578692,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.001029625135802862 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_mean",
            "value": 0.2881332390833222,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.28811619908333574 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_median",
            "value": 0.2881104724999659,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.28809864150001374 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_stddev",
            "value": 0.000208838551365962,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00021134612680179604 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_cv",
            "value": 0.0007247985412247776,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0007335447554639771 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_mean",
            "value": 121.30011270742595,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 121.291639697101 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_median",
            "value": 121.24768027165675,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 121.23832165977717 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_stddev",
            "value": 0.1388883241560377,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.14001442232087785 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_cv",
            "value": 0.0011449974864494498,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.001154361691131663 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_mean",
            "value": 206.1063439141367,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 206.09494186459324 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_median",
            "value": 205.88825947827203,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 205.87526039339141 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_stddev",
            "value": 0.7401853807097836,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.7391485257927574 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_cv",
            "value": 0.0035912789808068336,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.003586446708034137 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_mean",
            "value": 209.4755341488302,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 209.4596806128442 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_median",
            "value": 209.14517748930157,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 209.12809238351642 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_stddev",
            "value": 0.8234175676899596,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.824913158799339 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_cv",
            "value": 0.003930853171162843,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.003938290922557411 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_mean",
            "value": 70.1358815974248,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 70.13108987584131 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_median",
            "value": 70.08436886821785,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 70.07980848533664 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_stddev",
            "value": 0.29785005598649134,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.29806627404604463 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_cv",
            "value": 0.004246757140605011,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.004250130356932072 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_mean",
            "value": 0.3235722292499853,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.323550333416667 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_median",
            "value": 0.3234570019999978,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.32343429849998984 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_stddev",
            "value": 0.00039548102479224464,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0003783911946008181 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_cv",
            "value": 0.001222234138290972,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0011694971555276602 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_mean",
            "value": 7.462849768816923,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 7.462405669890167 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_median",
            "value": 7.4553240374522565,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 7.455026269691104 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_stddev",
            "value": 0.02368731100432102,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.023512989911044727 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_cv",
            "value": 0.003174030261643085,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.003150859247161619 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_mean",
            "value": 3.5877402105565728,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 3.587547014958649 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_median",
            "value": 3.5763220826291273,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 3.5761375486239775 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_stddev",
            "value": 0.0311262016979264,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.03110687604618767 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_cv",
            "value": 0.008675712250942977,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.008670792582364587 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "erenari27@gmail.com",
            "name": "Eren Arı",
            "username": "ErenAri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "6c7797025598e6005fbaf34c30572804d00c808d",
          "message": "docs: enforce phase-1 product contract evidence and boundaries (#8)\n\n* docs: enforce phase-1 product contract evidence and boundaries\n\n* test: harden phase-2 correctness basis-set and CI evidence artifacts\n\n* test: tighten phase-3 canary and break-glass guardrails\n\n* test: extend phase-2 matrix with traversal and bind-alias checks\n\n* ci: add phase-4 portability artifact evidence trail\n\n* ci: enforce phase-5 perf artifact schema and evidence\n\n* ci: harden phase-6 meta-security evidence contracts",
          "timestamp": "2026-02-05T03:42:56+03:00",
          "tree_id": "f474182e5c76b26b05a573de6c125910b6f5594c",
          "url": "https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/commit/6c7797025598e6005fbaf34c30572804d00c808d"
        },
        "date": 1770252543917,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "PolicyBenchmark/ParsePolicy_mean",
            "value": 29476.215563972062,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 29472.07400750346 ns\nthreads: 1"
          },
          {
            "name": "PolicyBenchmark/ParsePolicy_median",
            "value": 29545.94233320501,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 29540.687572217226 ns\nthreads: 1"
          },
          {
            "name": "PolicyBenchmark/ParsePolicy_stddev",
            "value": 364.5969062108657,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 364.61714067696903 ns\nthreads: 1"
          },
          {
            "name": "PolicyBenchmark/ParsePolicy_cv",
            "value": 0.01236918984459125,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.012371614586205884 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_mean",
            "value": 1206.2088661584626,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1206.0796257943605 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_median",
            "value": 1204.4283638567156,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1204.310205796174 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_stddev",
            "value": 4.933334414531993,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.924022809451687 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_cv",
            "value": 0.004089950383339239,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.004082668095987923 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_mean",
            "value": 1525.6728687417872,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1525.5402625207769 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_median",
            "value": 1525.0316633401717,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1524.978195336527 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_stddev",
            "value": 2.1686805434208893,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 2.129248610960945 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_cv",
            "value": 0.0014214584186775154,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.001395734129915792 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_mean",
            "value": 3745.9503657625464,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 3745.6179573101704 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_median",
            "value": 3744.972066366788,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 3744.5600365851647 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_stddev",
            "value": 3.435065317431475,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 3.486013110349923 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_cv",
            "value": 0.0009170076968524419,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0009306910502034552 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_mean",
            "value": 21677.80268495866,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 21675.947929247563 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_median",
            "value": 21671.104688613024,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 21669.629277507756 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_stddev",
            "value": 24.84487984476789,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 25.329314415099773 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_cv",
            "value": 0.0011460977021442644,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0011685447159117176 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_mean",
            "value": 165119.7655171053,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 165108.28966572482 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_median",
            "value": 164638.8552259877,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 164625.4185499054 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_stddev",
            "value": 1204.4571138226224,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1205.0329255616746 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_cv",
            "value": 0.007294445398772378,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0072984398784661985 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_mean",
            "value": 1308496.2467289737,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1308389.682242986 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_median",
            "value": 1308247.7719626056,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1308116.2934579446 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_stddev",
            "value": 1347.7386197429394,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1339.1766441947677 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_cv",
            "value": 0.0010299904360536495,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0010235304224495286 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_mean",
            "value": 5237057.050994999,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 5236493.2195273535 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_median",
            "value": 5230362.429104494,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 5229621.231343257 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_stddev",
            "value": 18109.56032004971,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 17937.74152726238 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_cv",
            "value": 0.003457965063911045,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0034255255903647367 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_mean",
            "value": 28.61201449864257,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 28.609798551320775 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_median",
            "value": 28.60246563842315,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 28.600583195675835 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_stddev",
            "value": 0.03901153961137492,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.038087445733222994 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_cv",
            "value": 0.0013634670712621695,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0013312727688348119 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_mean",
            "value": 68.42295901283818,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 68.41780319947419 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_median",
            "value": 68.42266448201597,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 68.41882073165299 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_stddev",
            "value": 0.07294602068146581,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.07232320250854037 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_cv",
            "value": 0.0010661044440913314,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0010570816238820158 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_mean",
            "value": 81.84797195689073,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 81.84233713970578 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_median",
            "value": 81.8446360891167,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 81.83861722124212 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_stddev",
            "value": 0.03953506292574109,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.03981216817377648 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_cv",
            "value": 0.00048303045244131625,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00048644955123674767 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_mean",
            "value": 0.15554918866666867,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15553846808333324 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_median",
            "value": 0.15548327449999985,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15547828150000242 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_stddev",
            "value": 0.00028118747448874096,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0002791931820844259 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_cv",
            "value": 0.0018077077540488275,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0017950104917764903 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_mean",
            "value": 0.311210141666668,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.31119015241666637 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_median",
            "value": 0.31100546349999547,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.3109909064999954 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_stddev",
            "value": 0.0004670980492648032,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00046549148619508024 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_cv",
            "value": 0.001500908828880982,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0014958425984245574 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_mean",
            "value": 26.16323087040591,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 26.161402250666253 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_median",
            "value": 26.111932524883954,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 26.110619225901456 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_stddev",
            "value": 0.1746462816474119,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.17401460082357942 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_cv",
            "value": 0.006675256680357471,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.006651577738695094 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_mean",
            "value": 33.296762923192794,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 33.29409997066743 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_median",
            "value": 33.27608259481085,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 33.27444946734367 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_stddev",
            "value": 0.06037667440694692,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.06046590766355009 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_cv",
            "value": 0.0018132896145556438,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0018161147986226207 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_mean",
            "value": 1.3989578108188316,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.398821353911096 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_median",
            "value": 1.3989883125242202,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.398868549613411 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_stddev",
            "value": 0.00040226103064241813,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00037458168998031363 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_cv",
            "value": 0.00028754336087302625,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0002677837945016963 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_mean",
            "value": 5041.486029074943,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 5044.474202090572 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_median",
            "value": 5038.1558837453495,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 5041.926481293095 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_stddev",
            "value": 16.056620946684443,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 13.77308147910547 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_cv",
            "value": 0.0031848984315504796,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0027303304422485724 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_mean",
            "value": 32547.051848209263,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 32548.24497248333 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_median",
            "value": 32574.65893268332,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 32577.727347007913 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_stddev",
            "value": 123.41274544696698,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 124.1476169959833 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_cv",
            "value": 0.0037918256320889207,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0038142645510054122 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_mean",
            "value": 267037.78097890125,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 267018.76464394113 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_median",
            "value": 266908.52316250926,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 266879.22568907036 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_stddev",
            "value": 383.36690713943034,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 378.83596381011245 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_cv",
            "value": 0.0014356279689491586,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0014187615777313445 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_mean",
            "value": 803097.3458572803,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 803209.4144510454 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_median",
            "value": 800577.576878701,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 800679.5283242223 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_stddev",
            "value": 7587.993606622068,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 7587.777788943088 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_cv",
            "value": 0.009448410763357874,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00944682377027287 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_mean",
            "value": 4.503157411696269,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.502812380816176 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_median",
            "value": 4.502165261614649,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.5018120152540515 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_stddev",
            "value": 0.004380901054519517,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0044415986825364975 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_cv",
            "value": 0.0009728509696642604,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0009864054521701872 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_mean",
            "value": 4.6535755232100335,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.653180542002389 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_median",
            "value": 4.653549883548407,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.653055982521368 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_stddev",
            "value": 0.0010935135286945067,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0010471948120653455 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_cv",
            "value": 0.00023498351391108442,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00022504925450726428 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_mean",
            "value": 4.5303667355871875,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.529955478597781 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_median",
            "value": 4.530366050061844,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.52972591057065 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_stddev",
            "value": 0.009880894001397278,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.009716801528588127 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_cv",
            "value": 0.0021810362335084993,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0021450103813373243 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_mean",
            "value": 4.414810621219806,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.41437605178382 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_median",
            "value": 4.414632057961817,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.414216871695438 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_stddev",
            "value": 0.0031356292536351914,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0032567402980737143 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_cv",
            "value": 0.0007102522673484057,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.000737757784989271 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_mean",
            "value": 0.1555942346666607,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15557733166666546 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_median",
            "value": 0.15545233200001007,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15542388450001 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_stddev",
            "value": 0.0003410577187291793,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0003276295604827107 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_cv",
            "value": 0.002191968869925345,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.002105895228905702 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_mean",
            "value": 22.738780496838288,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 22.737361875157884 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_median",
            "value": 22.925379555367325,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 22.923421944976088 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_stddev",
            "value": 0.37020319368295396,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.3702872098906162 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_cv",
            "value": 0.016280696923673142,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.016285407776140477 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_mean",
            "value": 43.32022401478138,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 43.317707901956055 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_median",
            "value": 43.31940142726254,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 43.317695528736074 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_stddev",
            "value": 0.03481661251479699,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.03455286411138612 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_cv",
            "value": 0.0008037034273626365,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0007976614134245513 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_mean",
            "value": 60.673533959797936,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 60.66967884067541 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_median",
            "value": 60.58134058432308,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 60.578097739401095 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_stddev",
            "value": 0.2627894987944973,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.2627719556531209 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_cv",
            "value": 0.004331204755085152,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.004331190813506465 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_mean",
            "value": 34.67454943681466,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 34.6719710057322 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_median",
            "value": 34.403026726302144,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 34.400005183922495 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_stddev",
            "value": 0.5395094915974789,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.5397724749716747 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_cv",
            "value": 0.015559235818783873,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.015567977802082146 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_mean",
            "value": 54.533592438944446,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 54.529721631147815 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_median",
            "value": 54.522124347380505,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 54.51932559487855 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_stddev",
            "value": 0.17817048651252046,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.17831839878329245 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_cv",
            "value": 0.0032671694371134512,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0032701138654160225 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_mean",
            "value": 0.15558764875000006,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15557275191666517 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_median",
            "value": 0.15544285149999837,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15541781850001257 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_stddev",
            "value": 0.0003650161263422294,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0003533282287241195 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_cv",
            "value": 0.0023460482196034807,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.002271144685499842 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_mean",
            "value": 0.3130385005000041,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.3129795319166675 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_median",
            "value": 0.3116977045000055,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.3116812739999944 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_stddev",
            "value": 0.0036401218799286266,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.003508635029263786 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_cv",
            "value": 0.011628352020963566,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.011210429665406935 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_mean",
            "value": 140.0535377931811,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 140.04412506360043 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_median",
            "value": 140.03887274735476,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 140.02773434445857 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_stddev",
            "value": 0.18697714831019766,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.18776584765033089 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_cv",
            "value": 0.0013350405227628682,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0013407620459984155 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_mean",
            "value": 236.71450278763373,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 236.6989602774793 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_median",
            "value": 236.668986207163,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 236.6521588477037 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_stddev",
            "value": 0.2762978780303808,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.27560469665625187 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_cv",
            "value": 0.0011672198989778793,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0011643680070802334 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_mean",
            "value": 208.71224660590784,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 208.69760762098971 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_median",
            "value": 208.7487820353535,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 208.7320258258376 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_stddev",
            "value": 0.237882967293484,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.23739770099489688 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_cv",
            "value": 0.0011397652565287963,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0011375199922081939 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_mean",
            "value": 74.7807736166771,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 74.77667095244892 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_median",
            "value": 74.7714180124358,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 74.7687073021184 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_stddev",
            "value": 0.028948913034847732,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.02874234493567041 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_cv",
            "value": 0.000387117057430277,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0003843758296480983 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_mean",
            "value": 0.31097512291666846,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.3109586984166744 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_median",
            "value": 0.31085245000002715,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.31084072200002305 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_stddev",
            "value": 0.00034144703695950966,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0003372898677275926 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_cv",
            "value": 0.001097988269148483,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0010846773846333614 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_mean",
            "value": 9.187230435329285,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 9.186831547027825 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_median",
            "value": 9.181407849202708,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 9.18110678796112 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_stddev",
            "value": 0.011310737468682925,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.011220691969845929 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_cv",
            "value": 0.0012311367988755068,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0012213886705559663 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_mean",
            "value": 4.590853223206373,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.590633780734843 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_median",
            "value": 4.5899410946063055,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.5897703449245055 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_stddev",
            "value": 0.003415509858576818,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.003372212294894487 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_cv",
            "value": 0.0007439814981040357,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0007345853439772061 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "erenari27@gmail.com",
            "name": "Eren Arı",
            "username": "ErenAri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "bd7754075c6039ec00dd147cf9dda1145fc8c35b",
          "message": "docs: codify market-leadership super-phases and KPI gates (#9)\n\n* docs: codify market-leadership super-phases and KPI gates\n\n* test: raise phase-2 kernel matrix floor to 60 checks\n\n* docs: pull external validation into market execution gates\n\n* feat: enforce attach-contract safety to prevent false-green startup\n\n* test: enforce 1000-iteration rollback stress gate in phase-3 contract\n\n* feat: close super-phase B/C gates with soak ratio, perf KPI, and pilot evidence\n\n* docs: sync market evidence status and root design artifact ownership\n\n* chore: untrack generated packaging artifacts",
          "timestamp": "2026-02-05T19:58:24+03:00",
          "tree_id": "58fb92e04ebd05995282e36f8ddd3f60618cc9a4",
          "url": "https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/commit/bd7754075c6039ec00dd147cf9dda1145fc8c35b"
        },
        "date": 1770311079500,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "PolicyBenchmark/ParsePolicy_mean",
            "value": 28987.27936688747,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 28985.14237089201 ns\nthreads: 1"
          },
          {
            "name": "PolicyBenchmark/ParsePolicy_median",
            "value": 29002.728044739444,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 29001.811661143325 ns\nthreads: 1"
          },
          {
            "name": "PolicyBenchmark/ParsePolicy_stddev",
            "value": 156.98368601861253,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 156.80168220448053 ns\nthreads: 1"
          },
          {
            "name": "PolicyBenchmark/ParsePolicy_cv",
            "value": 0.0054156060674647845,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.005409726134791968 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_mean",
            "value": 1208.8122209058579,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1208.7387168733783 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_median",
            "value": 1202.4782605331475,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1202.4111807885238 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_stddev",
            "value": 13.532851325630352,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 13.514234432247166 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_cv",
            "value": 0.011195164221196511,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.011180443087985286 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_mean",
            "value": 1522.4949100656852,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1522.3909172140302 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_median",
            "value": 1517.8280873461265,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1517.6504404280297 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_stddev",
            "value": 16.99928930029877,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 16.99722867923732 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_cv",
            "value": 0.011165416178347267,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.011164825332998035 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_mean",
            "value": 3746.996889383247,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 3746.8221783408376 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_median",
            "value": 3745.4984518219812,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 3745.2937687840245 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_stddev",
            "value": 4.428044199693141,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.3905447113794445 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_cv",
            "value": 0.0011817581733893547,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00117180493292683 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_mean",
            "value": 21772.204543812375,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 21771.093270987494 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_median",
            "value": 21688.54055058372,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 21686.660808843993 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_stddev",
            "value": 231.60159344433706,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 231.89073830929354 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_cv",
            "value": 0.010637489326277613,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.010651313437635894 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_mean",
            "value": 165075.7710003136,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 165066.77306302066 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_median",
            "value": 164909.8617397429,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 164906.6390853372 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_stddev",
            "value": 413.42974433680115,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 413.5260024125975 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_cv",
            "value": 0.0025044847092431013,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0025052043772293155 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_mean",
            "value": 1311645.9038701644,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1311570.8795255946 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_median",
            "value": 1307574.0393258573,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1307493.0084269661 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_stddev",
            "value": 13825.579465451023,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 13808.619450355758 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_cv",
            "value": 0.010540634042051316,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.01052830591614724 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_mean",
            "value": 5225841.096393008,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 5225423.855099495 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_median",
            "value": 5221727.39925359,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 5221376.417910495 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_stddev",
            "value": 14835.229372833293,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 14927.718077517595 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_cv",
            "value": 0.002838821368501408,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0028567477952912133 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_mean",
            "value": 28.601382188579255,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 28.599325223622003 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_median",
            "value": 28.599269519032593,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 28.596790423161853 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_stddev",
            "value": 0.008715724329667815,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00823990222188548 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_cv",
            "value": 0.0003047308788156423,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0002881152669671948 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_mean",
            "value": 68.00054566896651,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 67.99597141908266 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_median",
            "value": 68.51530955438622,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 68.50644061945844 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_stddev",
            "value": 0.7301186717172206,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.7290062245831875 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_cv",
            "value": 0.010736953130810328,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.010721314945117414 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_mean",
            "value": 81.371687351586,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 81.3665409485122 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_median",
            "value": 81.05707486919047,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 81.05143494162657 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_stddev",
            "value": 0.809655780277465,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.8086107321505763 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_cv",
            "value": 0.009950092060634701,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.009937877691792942 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_mean",
            "value": 0.1556412415833369,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15563290433333535 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_median",
            "value": 0.15555465100000274,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.1555505249999953 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_stddev",
            "value": 0.00038758188569055027,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0003859898803125576 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_cv",
            "value": 0.0024902261235369458,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.002480130290994521 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_mean",
            "value": 0.3110194766666699,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.3109980536666654 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_median",
            "value": 0.3108551250000033,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.31083793049999286 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_stddev",
            "value": 0.00034462965994894423,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00033189124362102126 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_cv",
            "value": 0.0011080645612374157,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0010671810955342814 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_mean",
            "value": 26.10912413463606,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 26.107319246876717 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_median",
            "value": 26.10871689862218,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 26.10629819928236 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_stddev",
            "value": 0.00624312208926447,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.005724833570574037 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_cv",
            "value": 0.00023911648882094885,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00021928078928513164 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_mean",
            "value": 33.36201015789174,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 33.35990821851523 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_median",
            "value": 33.26064873322327,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 33.25977622366171 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_stddev",
            "value": 0.3374025097427434,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.33678643399984637 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_cv",
            "value": 0.01011337470811636,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.01009554438201137 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_mean",
            "value": 1.8674442330993999,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.8673229905605293 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_median",
            "value": 1.8658862125192641,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.8657542903165834 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_stddev",
            "value": 0.005614628835037174,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.005616285313033895 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_cv",
            "value": 0.003006584472789619,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0030076667729282388 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_mean",
            "value": 4784.861833447678,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4792.8220204814 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_median",
            "value": 4783.554785674532,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4791.0166453805205 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_stddev",
            "value": 5.219103543498909,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 5.196634347696611 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_cv",
            "value": 0.0010907532391041567,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0010842535619911568 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_mean",
            "value": 33239.63459624249,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 33243.06348925261 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_median",
            "value": 33166.54009103828,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 33168.971329715205 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_stddev",
            "value": 164.1934656395285,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 164.82810861848884 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_cv",
            "value": 0.004939689248512059,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.004958270728321333 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_mean",
            "value": 270385.4907872983,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 270383.0495748209 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_median",
            "value": 270514.7777347882,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 270511.6575184146 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_stddev",
            "value": 675.1069178234997,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 677.3027837977004 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_cv",
            "value": 0.0024968311570925964,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0025049750154928847 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_mean",
            "value": 814278.7850467457,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 814396.8296339543 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_median",
            "value": 808405.669391961,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 808556.8119158531 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_stddev",
            "value": 11392.632423614019,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 11393.14870641659 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_cv",
            "value": 0.013991071157478325,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.013989677135085915 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_mean",
            "value": 4.503269982694137,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.503061268357346 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_median",
            "value": 4.503116492912705,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.502876664055447 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_stddev",
            "value": 0.002062057866549819,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.002021356600169412 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_cv",
            "value": 0.00045790234084880854,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0004488849872803918 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_mean",
            "value": 4.658497367543894,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.6582788228898755 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_median",
            "value": 4.655950221637294,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.65569700593988 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_stddev",
            "value": 0.009711117372363257,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.009789210787675412 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_cv",
            "value": 0.0020846029537381207,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0021014651891537997 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_mean",
            "value": 4.55693680204639,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.556742959399181 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_median",
            "value": 4.557641769162465,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.557387174446789 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_stddev",
            "value": 0.0027146448527027873,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.002691094356089526 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_cv",
            "value": 0.0005957170289225249,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0005905740964691925 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_mean",
            "value": 4.41923570481121,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.418932747884116 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_median",
            "value": 4.416673909218621,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.416445233458303 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_stddev",
            "value": 0.009413935100034502,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.009441200461619701 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_cv",
            "value": 0.0021302179220233884,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0021365340909839277 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_mean",
            "value": 0.15543749866667156,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15542850841666458 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_median",
            "value": 0.15539500350001842,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.1553896100000003 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_stddev",
            "value": 0.0001906151697049337,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00018899891783678998 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_cv",
            "value": 0.0012263139290069186,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.001215986177581603 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_mean",
            "value": 21.967479561992054,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 21.966540701252313 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_median",
            "value": 21.972066128253278,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 21.971249840227525 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_stddev",
            "value": 0.030101372135723795,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.02995466578345091 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_cv",
            "value": 0.001370269723059396,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0013636496611295378 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_mean",
            "value": 43.23570502684104,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 43.233537994541784 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_median",
            "value": 43.046845904878616,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 43.04457451320892 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_stddev",
            "value": 0.5229844114221068,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.5236753175744397 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_cv",
            "value": 0.012096123125491638,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.012112710221415454 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_mean",
            "value": 62.13988324734006,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 62.13590652965623 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_median",
            "value": 62.059207472217714,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 62.05533829803744 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_stddev",
            "value": 0.20047520634985583,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.19896312201922609 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_cv",
            "value": 0.0032261921953069856,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.003202063559244363 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_mean",
            "value": 34.7603385953222,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 34.75852786846934 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_median",
            "value": 34.30635565564901,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 34.305307885109606 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_stddev",
            "value": 0.6173650310141422,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.6173797570847287 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_cv",
            "value": 0.017760616149384192,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.017761965046994267 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_mean",
            "value": 55.39193621767606,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 55.38915996917655 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_median",
            "value": 55.078760501541545,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 55.07586406808229 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_stddev",
            "value": 0.5754386966835497,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.575035312553216 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_cv",
            "value": 0.010388492188144926,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.010381730159352781 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_mean",
            "value": 0.15549547524999244,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15548262733333235 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_median",
            "value": 0.1554416124999989,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15543115299999502 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_stddev",
            "value": 0.0001754378562062405,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00016470106249868554 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_cv",
            "value": 0.0011282505547134823,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0010592891651206163 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_mean",
            "value": 0.31143219275000905,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.31140866358333597 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_median",
            "value": 0.311397578000026,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.31137717299999684 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_stddev",
            "value": 0.00035499905207487706,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00034553543359646576 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_cv",
            "value": 0.0011398919583109372,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0011095883769591953 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_mean",
            "value": 140.03107650408916,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 140.01947636402915 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_median",
            "value": 140.02547075816588,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 140.01394823414748 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_stddev",
            "value": 0.09685750799567211,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.10129500914529134 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_cv",
            "value": 0.0006916858058492729,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0007234351375657189 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_mean",
            "value": 235.53780196971002,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 235.516516723593 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_median",
            "value": 235.49046542766908,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 235.47025742148548 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_stddev",
            "value": 0.29531874217814563,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.29533133664715977 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_cv",
            "value": 0.0012538061394328686,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0012539729304580647 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_mean",
            "value": 211.1669954705666,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 211.14720825033643 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_median",
            "value": 210.56921362603495,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 210.54820172013135 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_stddev",
            "value": 1.016194628221358,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.020503539119651 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_cv",
            "value": 0.004812279617640342,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.004833137731613959 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_mean",
            "value": 74.59516468866495,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 74.58910032687369 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_median",
            "value": 74.5914508230962,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 74.58573531985483 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_stddev",
            "value": 0.053204447314416474,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.051917789183730585 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_cv",
            "value": 0.0007132425745887671,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0006960506153876366 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_mean",
            "value": 0.3112148620833371,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.3111921614999981 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_median",
            "value": 0.31091870649999004,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.31087594350000813 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_stddev",
            "value": 0.0010769848654725673,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0010739687551209276 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_cv",
            "value": 0.0034605830141369418,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0034511433383932915 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_mean",
            "value": 10.013276003007157,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 10.01252134238389 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_median",
            "value": 10.0149025358425,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 10.014262196652368 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_stddev",
            "value": 0.023187722706771736,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.02337354329156313 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_cv",
            "value": 0.0023156979493832064,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.002334431307788664 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_mean",
            "value": 4.05343565269038,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.053215530003052 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_median",
            "value": 4.044458075194794,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.044114252518641 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_stddev",
            "value": 0.031054008090279014,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.031099329308684417 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_cv",
            "value": 0.007661157287563599,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.007672754897556854 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "erenari27@gmail.com",
            "name": "Eren Arı",
            "username": "ErenAri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "dcce0f3c1aeb2ee789412c066df02e8d8844d935",
          "message": "feat/roadmap exec (#10)\n\n* docs: add production roadmap and versioned contract refs\n\n* docs: add edge-case compliance suite\n\n* docs: add differentiation KPIs to pilot evidence\n\n* feat: add doctor diagnostics command\n\n* feat: expand e2e matrix to 100+ enforcement checks\n\n* feat: add reference enforcement slice gate\n\n* test: require differentiation KPIs in pilot evidence\n\n* feat: add overlayfs and namespace e2e coverage\n\n* test: add ringbuf metrics regression checks\n\n* feat: add explain CLI for decision tracing\n\n* feat: add policy lint fix output\n\n* docs: add production deployment blueprint\n\n* docs: document dry-run traces in blueprint\n\n* docs: add explainability evidence to readiness\n\n* docs: add design PDF generation script\n\n* docs: note PDF generation dependency\n\n* docs: refresh design PDF\n\n* docs: normalize diagrams and refresh PDF\n\n* docs: update design artifact sync status\n\n* docs: remove market leadership wording\n\n* docs: refresh design PDF after rename\n\n* docs: record PDF generation commit\n\n* docs: keep only public-facing documentation\n\n* ci: suppress cppcheck syntax error in test_metrics",
          "timestamp": "2026-02-05T22:32:56+03:00",
          "tree_id": "2b6210d97bccbfa52f19a75ecd74a56dc8881a90",
          "url": "https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/commit/dcce0f3c1aeb2ee789412c066df02e8d8844d935"
        },
        "date": 1770320343589,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "PolicyBenchmark/ParsePolicy_mean",
            "value": 29270.683817025874,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 29263.562154505253 ns\nthreads: 1"
          },
          {
            "name": "PolicyBenchmark/ParsePolicy_median",
            "value": 29177.116728855603,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 29159.850849917075 ns\nthreads: 1"
          },
          {
            "name": "PolicyBenchmark/ParsePolicy_stddev",
            "value": 334.85057099913644,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 336.38760564202204 ns\nthreads: 1"
          },
          {
            "name": "PolicyBenchmark/ParsePolicy_cv",
            "value": 0.011439793244746949,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.011495101104437268 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_mean",
            "value": 1208.5965183472729,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1208.5087223496992 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_median",
            "value": 1205.1555511756117,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1205.0807057981065 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_stddev",
            "value": 8.893892659070621,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 8.890944697280577 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_cv",
            "value": 0.0073588600695563885,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.007356955339133957 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_mean",
            "value": 1508.4051178262691,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1508.2833263358843 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_median",
            "value": 1507.8935795717452,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1507.7610995683117 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_stddev",
            "value": 1.2939512315098212,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.310811676514339 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_cv",
            "value": 0.0008578273941250655,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0008690752285240274 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_mean",
            "value": 3627.5019990929254,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 3627.2023683883817 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_median",
            "value": 3624.7362568289227,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 3624.478613111509 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_stddev",
            "value": 6.100275760096576,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 6.139474255918587 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_cv",
            "value": 0.0016816739898756717,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.001692619719656404 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_mean",
            "value": 20682.37912247532,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 20681.020704698283 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_median",
            "value": 20683.1415994563,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 20681.8492717658 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_stddev",
            "value": 7.8433244627936425,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 7.814476373135784 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_cv",
            "value": 0.00037922738077411926,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0003778573835749075 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_mean",
            "value": 156704.60209218986,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 156692.65191690926 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_median",
            "value": 156670.917095547,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 156660.61848288245 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_stddev",
            "value": 94.90894670545681,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 93.43041645654482 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_cv",
            "value": 0.0006056551335334846,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0005962654618040988 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_mean",
            "value": 1249226.9159239393,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1249132.3458110504 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_median",
            "value": 1247422.1818181847,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1247298.3030303088 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_stddev",
            "value": 3609.464231525951,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 3582.544935805672 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_cv",
            "value": 0.0028893583587705197,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0028680267129577515 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_mean",
            "value": 4992815.161904793,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4992508.8845238 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_median",
            "value": 4990467.357142795,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4990122.892857128 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_stddev",
            "value": 8849.687483204838,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 8881.893526109281 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_cv",
            "value": 0.0017724844994719614,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0017790441101952013 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_mean",
            "value": 28.62070695177019,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 28.619030100736158 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_median",
            "value": 28.61472153253638,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 28.61214505421067 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_stddev",
            "value": 0.0344855216095947,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.03441082038369219 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_cv",
            "value": 0.0012049150870978664,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.001202375491502315 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_mean",
            "value": 68.0731525425832,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 68.06886375725084 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_median",
            "value": 68.07225320381255,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 68.06918505131024 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_stddev",
            "value": 0.040727863702809744,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.04112044057440861 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_cv",
            "value": 0.0005982955420983685,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0006041005873265863 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_mean",
            "value": 81.52317346689438,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 81.51752386818444 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_median",
            "value": 81.5307551271261,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 81.5242892726883 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_stddev",
            "value": 0.04070053966486545,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.040895281066242684 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_cv",
            "value": 0.0004992511691340558,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0005016747212828891 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_mean",
            "value": 0.1554165190833293,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15540702166666875 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_median",
            "value": 0.1553633164999866,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15535662600000677 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_stddev",
            "value": 0.0001470229103341224,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00014821242360900846 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_cv",
            "value": 0.0009459928146717371,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0009537048070254385 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_mean",
            "value": 0.3109744256666645,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.31095774649999913 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_median",
            "value": 0.3109089699999998,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.3108849315000057 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_stddev",
            "value": 0.0002183686708900049,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00022030539431376365 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_cv",
            "value": 0.0007022078115326298,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0007084737292877322 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_mean",
            "value": 26.110665191181123,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 26.109213098313642 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_median",
            "value": 26.1079154983522,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 26.106107429814255 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_stddev",
            "value": 0.00858236712861348,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.008920928063705981 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_cv",
            "value": 0.0003286920140017028,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00034167740062155197 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_mean",
            "value": 33.263265945669936,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 33.26110419919871 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_median",
            "value": 33.26270453611653,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 33.26115954012951 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_stddev",
            "value": 0.013224633114013775,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.013284502988810344 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_cv",
            "value": 0.0003975747040478236,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0003994005403203174 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_mean",
            "value": 1.7096874335297096,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.7095701855729013 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_median",
            "value": 1.7091639778550929,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.7090231054956713 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_stddev",
            "value": 0.001385708044210879,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0013877746980069737 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_cv",
            "value": 0.0008105037312873244,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0008117681916299391 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_mean",
            "value": 4645.754703169528,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4655.022903840182 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_median",
            "value": 4646.039713287565,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4654.035044467349 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_stddev",
            "value": 14.569390673630494,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 14.640137921508668 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_cv",
            "value": 0.0031360654198317123,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0031450195249160258 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_mean",
            "value": 32938.32200884818,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 32940.2637099902 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_median",
            "value": 32934.948857722164,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 32937.69939828774 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_stddev",
            "value": 77.18003355209146,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 76.65490782062669 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_cv",
            "value": 0.002343168347536303,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.002327088468249834 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_mean",
            "value": 269332.25895154965,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 269316.2734091555 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_median",
            "value": 269176.8448608918,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 269169.16924253694 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_stddev",
            "value": 877.4768276302683,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 879.6953169035501 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_cv",
            "value": 0.0032579715146120623,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.003266402381734592 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_mean",
            "value": 813374.1238398597,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 813432.4214036764 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_median",
            "value": 812239.9704176771,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 812297.1328305447 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_stddev",
            "value": 5842.8974473981625,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 5872.150691844298 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_cv",
            "value": 0.007183530033896845,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00721897792285091 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_mean",
            "value": 4.504221515370484,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.503748765434596 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_median",
            "value": 4.503154950851766,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.502856778729101 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_stddev",
            "value": 0.003715865615114389,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0037123890000005477 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_cv",
            "value": 0.0008249739943815238,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0008242886522650682 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_mean",
            "value": 4.655971121371125,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.655510084729721 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_median",
            "value": 4.654010575444549,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.6535325838786425 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_stddev",
            "value": 0.0032588835442114387,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0032405905246076622 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_cv",
            "value": 0.0006999363740150818,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0006960763623382415 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_mean",
            "value": 4.560181044730232,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.559683819791232 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_median",
            "value": 4.5604340568683766,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.560055294688127 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_stddev",
            "value": 0.01600772850551341,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.015965242666812967 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_cv",
            "value": 0.0035103274077269413,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.003501392486364097 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_mean",
            "value": 4.4210786564675475,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.420600095453784 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_median",
            "value": 4.420211971800832,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.419532980477016 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_stddev",
            "value": 0.003790109083970476,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.003796665857281521 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_cv",
            "value": 0.0008572815320591427,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0008588575703072695 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_mean",
            "value": 0.1556681141666729,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15565299233333718 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_median",
            "value": 0.15556880700000875,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15555409350000104 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_stddev",
            "value": 0.0003425486398542747,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0003406846118985583 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_cv",
            "value": 0.0022005061324730244,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0021887443780648206 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_mean",
            "value": 22.698968170655153,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 22.697001568918015 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_median",
            "value": 22.735890347299378,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 22.734207702034706 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_stddev",
            "value": 0.15009203755585743,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15000479478490505 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_cv",
            "value": 0.006612284594940041,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.006609013720575598 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_mean",
            "value": 43.87201372537984,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 43.868455301540855 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_median",
            "value": 43.94050770728726,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 43.93660744553037 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_stddev",
            "value": 0.44138361151602085,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.44184320662820586 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_cv",
            "value": 0.01006071009821648,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.010072002845577433 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_mean",
            "value": 62.076925710416596,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 62.071866032498086 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_median",
            "value": 62.068491985675756,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 62.062842631215794 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_stddev",
            "value": 0.06837599028436445,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.06824079433605552 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_cv",
            "value": 0.0011014719157216714,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0010993836450853217 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_mean",
            "value": 34.48203318421776,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 34.479551987529184 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_median",
            "value": 34.2097718514996,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 34.2067347875845 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_stddev",
            "value": 0.8812265356501171,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.8809241567998272 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_cv",
            "value": 0.025556107174487898,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.025549176425449092 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_mean",
            "value": 53.785900465381445,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 53.781332876968655 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_median",
            "value": 53.48216335739128,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 53.4769507959791 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_stddev",
            "value": 0.587940178626232,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.5876968971805877 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_cv",
            "value": 0.010931120861398457,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.010927525699763076 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_mean",
            "value": 0.15573028133333836,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15571579666666696 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_median",
            "value": 0.15557580099996926,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.1555567445000037 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_stddev",
            "value": 0.0007095152681596715,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0007076533798999405 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_cv",
            "value": 0.004556052054134317,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.004544518893062461 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_mean",
            "value": 0.6226336452500002,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.6225866824999974 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_median",
            "value": 0.6222560875000056,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.6222148935000006 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_stddev",
            "value": 0.0013825085039047794,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0013826835104118358 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_cv",
            "value": 0.0022204204903666486,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.002220869076189791 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_mean",
            "value": 137.40942284680898,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 137.39944445782126 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_median",
            "value": 136.54395443427023,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 136.52903009288823 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_stddev",
            "value": 1.5717603494381571,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.572153261830173 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_cv",
            "value": 0.011438519403363157,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.011442209741341356 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_mean",
            "value": 235.50746452664126,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 235.48857253118572 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_median",
            "value": 235.28987247925474,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 235.26558545923464 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_stddev",
            "value": 1.4375304127722508,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.4375183784987424 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_cv",
            "value": 0.0061039696370627505,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.006104408222646865 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_mean",
            "value": 212.83866982184293,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 212.82515640220836 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_median",
            "value": 212.88051368181007,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 212.86380236500892 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_stddev",
            "value": 0.21483738942440267,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.21504748558295414 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_cv",
            "value": 0.0010093907728526625,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0010104420418070592 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_mean",
            "value": 74.67195504647457,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 74.66701098363134 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_median",
            "value": 74.66943385547793,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 74.66513267461231 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_stddev",
            "value": 0.0557713362178456,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.055634006891087766 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_cv",
            "value": 0.0007468846393955328,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0007450948706555826 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_mean",
            "value": 0.3110917966666638,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.3110711673333384 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_median",
            "value": 0.3109101184999758,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.31089176500000804 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_stddev",
            "value": 0.00046355016143932146,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00046588804988668617 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_cv",
            "value": 0.0014900751688287604,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.001497689592643759 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_mean",
            "value": 9.998929438941321,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 9.996577360931239 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_median",
            "value": 9.995479689070004,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 9.994971743340093 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_stddev",
            "value": 0.0792951921166266,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.07856777701853286 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_cv",
            "value": 0.007930368206000892,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00785946771397904 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_mean",
            "value": 4.060272011843243,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.059988705044053 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_median",
            "value": 4.045883532334545,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.045590411770602 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_stddev",
            "value": 0.027681780936157908,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.027694874528670834 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_cv",
            "value": 0.00681771587110766,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.006821416644401804 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "erenari27@gmail.com",
            "name": "Eren Arı",
            "username": "ErenAri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "f897efb6d722d9c5c4f1f3a19fe5a5592f3c98d7",
          "message": "docs: add public evidence pack artifacts (#11)\n\n* docs: add public evidence pack artifacts\n\n* docs: publish external validation and chaos evidence\n\n* ops: add self-hosted runner setup script\n\n* chore: align kernel matrix with 6.8\n\n* chore: retrigger kernel matrix\n\n* chore: retrigger kernel-matrix",
          "timestamp": "2026-02-06T03:24:36+03:00",
          "tree_id": "e7fbc8b02a09ed9a21faa3021fd2b093ba110aeb",
          "url": "https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/commit/f897efb6d722d9c5c4f1f3a19fe5a5592f3c98d7"
        },
        "date": 1770337841407,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "PolicyBenchmark/ParsePolicy_mean",
            "value": 29112.467733233643,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 29110.96477631142 ns\nthreads: 1"
          },
          {
            "name": "PolicyBenchmark/ParsePolicy_median",
            "value": 29001.46034611539,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 28999.103834661353 ns\nthreads: 1"
          },
          {
            "name": "PolicyBenchmark/ParsePolicy_stddev",
            "value": 285.40106238390047,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 285.02349902297163 ns\nthreads: 1"
          },
          {
            "name": "PolicyBenchmark/ParsePolicy_cv",
            "value": 0.009803396434789271,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.009790932770971058 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_mean",
            "value": 1208.4392795674578,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1208.3794328174606 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_median",
            "value": 1205.718780669781,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1205.633638379372 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_stddev",
            "value": 7.351058037926528,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 7.334646496157679 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_cv",
            "value": 0.006083100874176918,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.006069820701148643 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_mean",
            "value": 1513.6122140066248,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1513.5438065061335 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_median",
            "value": 1512.3369143516409,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1512.2642504068738 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_stddev",
            "value": 3.079231265399342,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 3.0896210773464823 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_cv",
            "value": 0.002034359419740957,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0020413159262820195 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_mean",
            "value": 3636.6453077234514,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 3636.514694049212 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_median",
            "value": 3635.2907101631076,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 3635.0939567572636 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_stddev",
            "value": 4.502477894591185,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.540675595358984 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_cv",
            "value": 0.0012380855193738281,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0012486339193924722 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_mean",
            "value": 20687.742115187695,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 20686.954520166164 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_median",
            "value": 20679.34145693007,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 20678.630642207274 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_stddev",
            "value": 20.038557053276964,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 20.148282876576193 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_cv",
            "value": 0.0009686198204571518,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0009739608049573048 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_mean",
            "value": 156671.130973716,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 156664.5297005675 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_median",
            "value": 156561.47860663274,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 156553.91050627208 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_stddev",
            "value": 216.74501095504374,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 216.74862308432213 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_cv",
            "value": 0.0013834393714270568,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.001383520720986385 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_mean",
            "value": 1246292.5769572936,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1246243.1284104383 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_median",
            "value": 1246043.338078298,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1245991.2197508852 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_stddev",
            "value": 1020.8278527881972,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1031.0675512249206 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_cv",
            "value": 0.000819091657659113,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0008273406109288077 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_mean",
            "value": 4984362.949404761,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4984170.595238089 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_median",
            "value": 4982882.435714231,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4982697.821428569 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_stddev",
            "value": 3906.008506705643,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 3954.328270842776 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_cv",
            "value": 0.0007836525041123065,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00079337739254366 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_mean",
            "value": 28.598965714951177,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 28.59775019846838 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_median",
            "value": 28.59470393009344,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 28.59407396847649 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_stddev",
            "value": 0.022152643067308315,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.022272102483431134 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_cv",
            "value": 0.000774595951759444,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0007788061063846893 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_mean",
            "value": 67.92254283830606,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 67.9197825257444 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_median",
            "value": 67.90316415556136,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 67.90027387988017 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_stddev",
            "value": 0.06160679813378661,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.06158108184754671 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_cv",
            "value": 0.0009070154849833216,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0009066737194602317 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_mean",
            "value": 81.51561630089981,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 81.51220862555307 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_median",
            "value": 81.50970046155864,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 81.50768337138379 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_stddev",
            "value": 0.060602538044115944,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0603645980328699 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_cv",
            "value": 0.0007434469711964501,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0007405589794550892 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_mean",
            "value": 0.15567505958333783,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15567006825000124 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_median",
            "value": 0.1554415155000157,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15543525500000044 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_stddev",
            "value": 0.0006347796606679601,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0006344741700514597 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_cv",
            "value": 0.0040775938186048515,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.004075762137089284 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_mean",
            "value": 0.31133789183334193,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.3113256923333326 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_median",
            "value": 0.3112594225000009,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.31125834950000103 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_stddev",
            "value": 0.0005792967180457537,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0005836644356271408 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_cv",
            "value": 0.0018606688528483041,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.001874771180151166 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_mean",
            "value": 26.11159714116906,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 26.11084212760532 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_median",
            "value": 26.106081750107876,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 26.105357766884353 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_stddev",
            "value": 0.01665332378559497,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.016765388161302557 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_cv",
            "value": 0.0006377749968935592,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0006420853099784778 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_mean",
            "value": 33.296327130297065,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 33.29526320746842 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_median",
            "value": 33.27741802503829,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 33.27565955122022 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_stddev",
            "value": 0.04385180878115136,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.04409813026994449 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_cv",
            "value": 0.0013170163967199141,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0013244565749536677 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_mean",
            "value": 1.709779270133116,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.7097142692422533 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_median",
            "value": 1.7093354376468994,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.7092956449485832 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_stddev",
            "value": 0.0014025610407199178,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.001399871763991573 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_cv",
            "value": 0.0008203170229164847,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0008187752709182203 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_mean",
            "value": 4618.754209117858,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4621.004920530056 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_median",
            "value": 4613.424334973149,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4615.481405373986 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_stddev",
            "value": 24.560391363192,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 25.021683115772102 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_cv",
            "value": 0.0053175359092950784,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0054147709310168775 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_mean",
            "value": 33181.60012373553,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 33187.352927422726 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_median",
            "value": 33148.80581984242,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 33154.811459043565 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_stddev",
            "value": 125.65470434494823,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 125.90861771716824 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_cv",
            "value": 0.0037868789894512844,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.003793873467176404 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_mean",
            "value": 269998.0756456954,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 269993.78782296163 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_median",
            "value": 269917.3364341279,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 269917.2746121289 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_stddev",
            "value": 817.0367050793158,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 815.6730766698971 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_cv",
            "value": 0.003026083438281505,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0030210809042937846 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_mean",
            "value": 810114.4951660099,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 810234.1304137614 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_median",
            "value": 811695.6055685187,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 811837.4153132606 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_stddev",
            "value": 2921.8898577222485,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 2921.3623724236168 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_cv",
            "value": 0.0036067616061153072,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00360557802092559 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_mean",
            "value": 4.504062088977337,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.503896593569943 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_median",
            "value": 4.502200980392127,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.501960860629962 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_stddev",
            "value": 0.004643215443062476,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.004645265234103575 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_cv",
            "value": 0.0010308950790056126,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00103138807421455 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_mean",
            "value": 4.676336765973117,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.676131478520787 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_median",
            "value": 4.659954674664056,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.659655312992638 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_stddev",
            "value": 0.02437565553936032,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.024324774839854905 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_cv",
            "value": 0.005212553492025482,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.005201901390409497 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_mean",
            "value": 4.507788518405399,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.507630009369171 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_median",
            "value": 4.507233811172031,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.507048641446665 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_stddev",
            "value": 0.0017633003646500044,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.001753464964709416 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_cv",
            "value": 0.0003911674998617194,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0003889993102949476 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_mean",
            "value": 4.418186197111408,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.41750021650768 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_median",
            "value": 4.416184116491409,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.415782153884044 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_stddev",
            "value": 0.008856578419476823,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.007330748327908875 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_cv",
            "value": 0.00200457337566878,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0016594788836715227 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_mean",
            "value": 0.15561269100000172,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15560597066667017 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_median",
            "value": 0.15556889850003588,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15555766500000345 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_stddev",
            "value": 0.0002072246247198079,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00020642318419902245 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_cv",
            "value": 0.001331669180631325,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0013265762445658974 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_mean",
            "value": 21.961721201848746,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 21.960904069849523 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_median",
            "value": 21.960879724850518,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 21.960111974865878 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_stddev",
            "value": 0.02363029448453088,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.023694271919312716 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_cv",
            "value": 0.0010759764349682057,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0010789297127272173 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_mean",
            "value": 43.18777465183924,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 43.1861288383094 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_median",
            "value": 43.24151871564505,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 43.240731760273434 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_stddev",
            "value": 0.12624269282135703,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.1260460387947227 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_cv",
            "value": 0.002923111779642963,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0029186695400887663 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_mean",
            "value": 60.55394185092152,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 60.551459063219845 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_median",
            "value": 60.4192685314621,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 60.41787764737756 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_stddev",
            "value": 0.3557853153625283,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.3555207990201727 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_cv",
            "value": 0.005875510404234963,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.005871382862120379 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_mean",
            "value": 34.97014470216849,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 34.9688455077745 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_median",
            "value": 34.65686959315535,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 34.65564876504698 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_stddev",
            "value": 1.0897572152311343,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.0894858830584155 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_cv",
            "value": 0.03116250231482625,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.03115590083796715 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_mean",
            "value": 52.664165832473536,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 52.66258206832709 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_median",
            "value": 52.66299948189545,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 52.66181774578089 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_stddev",
            "value": 0.09052535639140667,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0903281926886556 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_cv",
            "value": 0.0017189175022608513,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0017152252916778604 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_mean",
            "value": 0.15548673291667112,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15548103874999458 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_median",
            "value": 0.15550806249999025,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.1555010324999984 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_stddev",
            "value": 0.00013542961110390623,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00013077656468352738 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_cv",
            "value": 0.0008710042880409998,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0008411094094490151 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_mean",
            "value": 0.6224050217500073,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.6223827644166656 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_median",
            "value": 0.622392697500004,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.6223737604999825 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_stddev",
            "value": 0.00033078577556107575,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0003250803679414349 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_cv",
            "value": 0.0005314638603509498,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0005223158264128984 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_mean",
            "value": 136.68980061981168,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 136.66922721275313 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_median",
            "value": 136.4408246689016,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 136.4341983419409 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_stddev",
            "value": 0.9075548270323828,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.8525839294352879 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_cv",
            "value": 0.006639521185319827,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.006238302116891826 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_mean",
            "value": 234.75389104120356,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 234.74352699035248 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_median",
            "value": 235.08167386676948,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 235.07415553246645 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_stddev",
            "value": 0.7522036704840521,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.7532166909419885 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_cv",
            "value": 0.0032042223758158147,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0032086792790369215 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_mean",
            "value": 214.0267914657119,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 214.01688999245928 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_median",
            "value": 213.00335833574684,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 212.99566881912324 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_stddev",
            "value": 1.4969055930521022,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.4936151266049842 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_cv",
            "value": 0.006994010342354327,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00697895912167311 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_mean",
            "value": 74.61307249586154,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 74.6101998251288 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_median",
            "value": 74.60465497722993,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 74.60063369943454 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_stddev",
            "value": 0.052113580073972404,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.051707666158903154 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_cv",
            "value": 0.0006984510666929433,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0006930374972871732 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_mean",
            "value": 0.3126285620833234,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.31261435000000876 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_median",
            "value": 0.31099754699999943,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.31097472350001 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_stddev",
            "value": 0.005640300845715401,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.005630968582494432 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_cv",
            "value": 0.018041540440607982,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.018012508326934688 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_mean",
            "value": 10.084778747095202,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 10.084324355031017 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_median",
            "value": 10.080085561869288,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 10.079485900910749 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_stddev",
            "value": 0.02513449486628432,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.025260064942652025 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_cv",
            "value": 0.0024923199106895635,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.002504884219640348 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_mean",
            "value": 4.00046358131985,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.000300600301936 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_median",
            "value": 3.978781869228076,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 3.978571240001244 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_stddev",
            "value": 0.03907679863165203,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.03905613710759511 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_cv",
            "value": 0.009768067584497206,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.009763300564124408 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "erenari27@gmail.com",
            "name": "Eren Arı",
            "username": "ErenAri"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "9ab2bd20db145c3eb5ba7d658e2beca4dde99902",
          "message": "docs: refresh evidence links and kernel baselines (#12)\n\n* docs: refresh evidence links and kernel baselines\n\n* ci: harden kernel-matrix apt install",
          "timestamp": "2026-02-06T03:51:12+03:00",
          "tree_id": "13284849796f26581e015a484cbc61e9f62664e8",
          "url": "https://github.com/ErenAri/Aegis-BPF-CO-RE-Enforcement-Prototype/commit/9ab2bd20db145c3eb5ba7d658e2beca4dde99902"
        },
        "date": 1770339440826,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "PolicyBenchmark/ParsePolicy_mean",
            "value": 29127.86005162836,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 29124.16497908642 ns\nthreads: 1"
          },
          {
            "name": "PolicyBenchmark/ParsePolicy_median",
            "value": 29094.32320785172,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 29091.458048618893 ns\nthreads: 1"
          },
          {
            "name": "PolicyBenchmark/ParsePolicy_stddev",
            "value": 136.84910028870598,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 135.9535032185976 ns\nthreads: 1"
          },
          {
            "name": "PolicyBenchmark/ParsePolicy_cv",
            "value": 0.004698220193524159,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.004668065275561498 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_mean",
            "value": 1210.2535104135252,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1210.1705655929738 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_median",
            "value": 1206.7236496916778,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1206.6459919796462 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_stddev",
            "value": 10.253871136285612,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 10.239372007693861 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Short_cv",
            "value": 0.008472498569974831,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00846109821112419 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_mean",
            "value": 1511.3185106734654,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1510.9529693827308 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_median",
            "value": 1510.4181019521468,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1510.3447304595293 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_stddev",
            "value": 2.707810422982664,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 2.2299291600345676 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/64_cv",
            "value": 0.0017916874595653729,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0014758428655430352 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_mean",
            "value": 3639.7317225400184,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 3639.4204670251024 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_median",
            "value": 3640.1749925831955,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 3639.8688030562475 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_stddev",
            "value": 1.7577959796691747,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.8042916667754578 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/512_cv",
            "value": 0.00048294657784351245,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0004957634555070531 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_mean",
            "value": 20922.498774619096,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 20920.517505085056 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_median",
            "value": 20849.435794016856,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 20847.512457210967 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_stddev",
            "value": 174.70533724651398,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 174.17000755070885 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/4096_cv",
            "value": 0.008350118173191031,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.008325320227301937 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_mean",
            "value": 158274.85239761983,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 158261.57710403515 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_median",
            "value": 158017.57113821222,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 158005.995370371 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_stddev",
            "value": 921.9663231450154,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 922.2129786778487 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/32768_cv",
            "value": 0.005825096717378965,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00582714386873335 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_mean",
            "value": 1252721.3124627322,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1252613.3640429347 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_median",
            "value": 1252569.190518785,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1252435.7674418653 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_stddev",
            "value": 1790.4672158139383,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1779.380452937834 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/262144_cv",
            "value": 0.0014292621974268547,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.001420534463399549 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_mean",
            "value": 4983360.333333355,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4982974.474820142 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_median",
            "value": 4982828.165467628,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4982370.273381316 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_stddev",
            "value": 3159.6837386345546,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 3219.3653407527563 ns\nthreads: 1"
          },
          {
            "name": "BM_Sha256Long/1048576_cv",
            "value": 0.0006340468132516222,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0006460730146262605 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_mean",
            "value": 28.700430590778982,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 28.698107356754292 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_median",
            "value": 28.630961710537438,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 28.628819340814044 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_stddev",
            "value": 0.1415509516716079,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.14159475441551891 ns\nthreads: 1"
          },
          {
            "name": "BM_Trim_cv",
            "value": 0.0049320149125945895,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.004933940508874487 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_mean",
            "value": 68.26523238719885,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 68.26029145556467 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_median",
            "value": 68.05720925914021,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 68.05176031334598 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_stddev",
            "value": 0.6323137012127895,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.6335453137280306 ns\nthreads: 1"
          },
          {
            "name": "BM_JsonEscape_cv",
            "value": 0.009262602339450345,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.009281315684689817 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_mean",
            "value": 81.73872561716873,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 81.73098513286293 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_median",
            "value": 81.54428817633321,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 81.53559810582392 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_stddev",
            "value": 0.6631166299175996,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.664012069134985 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseInodeId_cv",
            "value": 0.008112637246430424,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.008124361502012466 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_mean",
            "value": 0.15567005266666215,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15565635341666587 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_median",
            "value": 0.1555601615000057,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15553999899999835 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_stddev",
            "value": 0.0003077612454714681,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00030906450879363906 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHash_cv",
            "value": 0.0019770099656256966,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0019855566574036683 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_mean",
            "value": 0.31166826591666325,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.3116389300833333 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_median",
            "value": 0.31143916049998666,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.311420127500007 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_stddev",
            "value": 0.0011518409084898375,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.001155233085649562 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdHashVarying_cv",
            "value": 0.00369572726662466,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0037069601199716884 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_mean",
            "value": 26.170460762653736,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 26.168282976786685 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_median",
            "value": 26.120322366772168,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 26.118255570116194 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_stddev",
            "value": 0.1345569021880993,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.13465787892101913 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyShort_cv",
            "value": 0.0051415564826476886,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.005145843120103494 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_mean",
            "value": 33.29556979782274,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 33.292578961288044 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_median",
            "value": 33.285989102370465,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 33.28375175261064 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_stddev",
            "value": 0.03447238702216456,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.03485509854217755 ns\nthreads: 1"
          },
          {
            "name": "BM_FillPathKeyLong_cv",
            "value": 0.0010353445587952897,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0010469329691372472 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_mean",
            "value": 1.71038485805585,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.7102519902867384 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_median",
            "value": 1.710307504360592,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1.710224799719952 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_stddev",
            "value": 0.0007723959202485727,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0007634255638983217 ns\nthreads: 1"
          },
          {
            "name": "BM_EncodeDev_cv",
            "value": 0.00045159188390298026,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0004463819181232626 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_mean",
            "value": 4594.717966852892,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4603.3809365919715 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_median",
            "value": 4589.279169455048,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4598.308342389124 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_stddev",
            "value": 25.971364933740613,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 26.225506380022086 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/100_cv",
            "value": 0.005652439414367244,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00569700981545048 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_mean",
            "value": 32923.51543933236,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 32929.34729368073 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_median",
            "value": 32874.06580100463,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 32880.30877978336 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_stddev",
            "value": 166.97305014980876,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 166.44997143877677 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/512_cv",
            "value": 0.0050715437863094355,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.005054760726178109 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_mean",
            "value": 269331.23627242603,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 269314.3299819977 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_median",
            "value": 269268.08623352187,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 269250.9766047434 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_stddev",
            "value": 1022.7357037037391,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 1020.6618262204588 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/4096_cv",
            "value": 0.003797315594947374,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0037898533891185253 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_mean",
            "value": 810403.2072205986,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 810479.6396631243 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_median",
            "value": 808126.648664357,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 808202.7032516004 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_stddev",
            "value": 5032.282743910825,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 5029.321324535941 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesInsert/10000_cv",
            "value": 0.006209603687490091,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.006205364179939643 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_mean",
            "value": 4.514683145334123,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.514372230990058 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_median",
            "value": 4.506814463543107,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.506465701193135 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_stddev",
            "value": 0.018690416237057708,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.018651817267437722 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/100_cv",
            "value": 0.00413991760559632,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.004131652489663473 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_mean",
            "value": 4.665662179716267,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.665238973208563 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_median",
            "value": 4.65813834125544,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.657766108101547 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_stddev",
            "value": 0.018486337011893273,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.01848165964465446 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/512_cv",
            "value": 0.0039622107859119534,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0039615676176055605 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_mean",
            "value": 4.520067040787347,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.519678893690267 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_median",
            "value": 4.5196403595467585,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.519119522856661 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_stddev",
            "value": 0.0032612068546631033,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0032756998383078745 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/4096_cv",
            "value": 0.0007214952400562263,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0007247638417147157 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_mean",
            "value": 4.43426795036402,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.433902238949607 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_median",
            "value": 4.431795192560118,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.431485718958044 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_stddev",
            "value": 0.013211484208277115,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.013179503468381225 ns\nthreads: 1"
          },
          {
            "name": "BM_DenyEntriesLookup/10000_cv",
            "value": 0.0029794059258851403,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.002972438894255696 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_mean",
            "value": 0.1570210145833452,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15701079824999672 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_median",
            "value": 0.15572003700000892,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15571134849999171 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_stddev",
            "value": 0.0028106042672598895,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0028139060785975366 ns\nthreads: 1"
          },
          {
            "name": "BM_PortKeyHash_cv",
            "value": 0.017899542139106793,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.017921736020456137 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_mean",
            "value": 22.071245525428086,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 22.069777725733093 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_median",
            "value": 22.05227466133527,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 22.050655085654 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_stddev",
            "value": 0.0860811386790933,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0861013345024217 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv4_cv",
            "value": 0.0039001486608410915,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0039013231384758627 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_mean",
            "value": 43.4361071144427,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 43.43319700952165 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_median",
            "value": 43.35588933536325,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 43.35207171358423 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_stddev",
            "value": 0.19201989351783888,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.19157195868567825 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6_cv",
            "value": 0.004420743622625229,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0044107266302243625 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_mean",
            "value": 60.7794751827144,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 60.77434586654159 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_median",
            "value": 60.6568114743859,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 60.6517892017888 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_stddev",
            "value": 0.39718672797264204,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.39671582714325737 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseIpv6Full_cv",
            "value": 0.006534882487527656,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.006527685678665006 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_mean",
            "value": 34.99675524833342,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 34.99378795291389 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_median",
            "value": 35.40628915481759,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 35.40351275757182 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_stddev",
            "value": 0.6634176393668424,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.6635415020658518 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV4_cv",
            "value": 0.018956547104418627,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.01896169408578129 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_mean",
            "value": 53.66714892401462,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 53.66328543338344 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_median",
            "value": 53.66099808464085,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 53.65734716614986 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_stddev",
            "value": 0.2833600374949154,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.2833725311007567 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseCidrV6_cv",
            "value": 0.005279953252148994,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.005280566197396353 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_mean",
            "value": 0.15569899766666614,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15569044783333413 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_median",
            "value": 0.15561206149999407,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.15560608799999898 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_stddev",
            "value": 0.0002757641508179092,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0002717470907088312 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv4LpmKeyConstruction_cv",
            "value": 0.0017711363268265155,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0017454320062058987 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_mean",
            "value": 0.623116940750009,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.6230642756666712 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_median",
            "value": 0.6226002595000182,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.622537404500008 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_stddev",
            "value": 0.0018699837891543957,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0018696291967797592 ns\nthreads: 1"
          },
          {
            "name": "BM_Ipv6LpmKeyConstruction_cv",
            "value": 0.00300101580756833,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.003000700360776228 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_mean",
            "value": 135.35055578624142,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 135.32967106085874 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_median",
            "value": 134.07969112239053,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 134.06778817819782 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_stddev",
            "value": 3.026748967224488,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 2.994684608163487 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv4_cv",
            "value": 0.022362294337413883,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.022128810220906805 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_mean",
            "value": 234.80015822576408,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 234.7868163497683 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_median",
            "value": 234.71696242055677,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 234.70253595726305 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_stddev",
            "value": 0.46738100734480564,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.4661716549188115 ns\nthreads: 1"
          },
          {
            "name": "BM_FormatIpv6_cv",
            "value": 0.0019905480936491166,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0019855103543136893 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_mean",
            "value": 211.13614509668344,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 211.12132900257356 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_median",
            "value": 210.99001339223332,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 210.97865029299524 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_stddev",
            "value": 0.4816122294335772,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.4797323215483491 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeToString_cv",
            "value": 0.0022810505951647328,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0022723062791183035 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_mean",
            "value": 74.82341090023071,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 74.81785809788326 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_median",
            "value": 74.68558356909348,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 74.68145464560368 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_stddev",
            "value": 0.4445723570189124,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.44217096965963004 ns\nthreads: 1"
          },
          {
            "name": "BM_BuildExecId_cv",
            "value": 0.005941621100536352,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.005909965627205517 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_mean",
            "value": 0.31117373200000503,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.31115105816665795 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_median",
            "value": 0.3111346904999834,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.311126189499987 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_stddev",
            "value": 0.0002439166354109846,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.00023523674726288977 ns\nthreads: 1"
          },
          {
            "name": "BM_InodeIdComparison_cv",
            "value": 0.0007838599802215331,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.000756021042155328 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_mean",
            "value": 10.009139112116886,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 10.008474137603743 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_median",
            "value": 10.000157914515013,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 9.999624882046556 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_stddev",
            "value": 0.04887149352174603,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.04884146040055038 ns\nthreads: 1"
          },
          {
            "name": "BM_ProtocolName_cv",
            "value": 0.004882687009773206,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.004880010651877864 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_mean",
            "value": 4.058826106763184,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.0585327921812135 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_median",
            "value": 4.046596590606,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 4.046275779799063 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_stddev",
            "value": 0.03955156499995203,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.0395529255808742 ns\nthreads: 1"
          },
          {
            "name": "BM_DirectionName_cv",
            "value": 0.009744582290442949,
            "unit": "ns/iter",
            "extra": "iterations: 12\ncpu: 0.009745621781613575 ns\nthreads: 1"
          }
        ]
      }
    ]
  }
}