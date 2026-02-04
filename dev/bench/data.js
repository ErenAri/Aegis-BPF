window.BENCHMARK_DATA = {
  "lastUpdate": 1770233560229,
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
      }
    ]
  }
}