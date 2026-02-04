window.BENCHMARK_DATA = {
  "lastUpdate": 1770240602117,
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
      }
    ]
  }
}