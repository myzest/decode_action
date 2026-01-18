//Sun Jan 18 2026 13:36:03 GMT+0000 (Coordinated Universal Time)
//Base:<url id="cv1cref6o68qmpt26ol0" type="url" status="parsed" title="GitHub - echo094/decode-js: JS混淆代码的AST分析工具 AST analysis tool for obfuscated JS code" wc="2165">https://github.com/echo094/decode-js</url>
//Modify:<url id="cv1cref6o68qmpt26olg" type="url" status="parsed" title="GitHub - smallfawn/decode_action: 世界上本来不存在加密，加密的人多了，也便成就了解密" wc="741">https://github.com/smallfawn/decode_action</url>
var _0x1a2b = {
  a: "o",
  b: "x",
  c: "q",
  d: "m",
  e: "z",
  f: "w",
  g: "v",
  h: "t",
  i: "u",
  j: "r",
  k: "s",
  l: "p",
  m: "n",
  n: "l",
  o: "k",
  p: "j",
  q: "i",
  r: "h",
  s: "g",
  t: "f",
  u: "e",
  v: "d",
  w: "c",
  x: "b",
  y: "a",
  z: "y",
  "0": "5",
  "1": "8",
  "2": "7",
  "3": "6",
  "4": "9",
  "5": "0",
  "6": "3",
  "7": "2",
  "8": "1",
  "9": "4"
};
var _0x2b3c = {};
for (var _0x3c4d in _0x1a2b) {
  if (_0x1a2b.hasOwnProperty(_0x3c4d)) {
    _0x2b3c[_0x1a2b[_0x3c4d]] = _0x3c4d;
  }
}
function _0x4d5e(_0x5e6f) {
  var _0x6f70 = "";
  _0x5e6f = _0x5e6f.toLowerCase();
  for (var _0x7071 = 0; _0x7071 < _0x5e6f.length; _0x7071++) {
    var _0x7172 = _0x5e6f[_0x7071];
    _0x6f70 += _0x1a2b[_0x7172] || _0x7172;
  }
  return _0x6f70;
}
function _0x7f80(_0x8081) {
  var _0x8182 = "";
  for (var _0x8283 = 0; _0x8283 < _0x8081.length; _0x8283++) {
    var _0x8384 = _0x8081[_0x8283];
    _0x8182 += _0x2b3c[_0x8384] || _0x8384;
  }
  return _0x8182;
}
var _21k1ka0 = new Set();
function _kakakkkakkkkkkksanann(_0x3f5dbe) {
  Interceptor.attach(_0x3f5dbe, {
    onEnter: function (_0x5704c4) {
      _0x5704c4[1] = ptr(0);
      this.callback = _0x5704c4[2];
      if (this.callback < 4096) {
        return;
      }
      if (_21k1ka0.has(this.callback.toString())) {
        return;
      }
      _21k1ka0.add(this.callback.toString());
      Interceptor.attach(this.callback, {
        onEnter: function (_0x23370c) {},
        onLeave: function (_0x347669) {
          _0x347669.replace(0);
        }
      });
    },
    onLeave: function (_0x4add0a) {}
  });
}
function snska100110921jrn(_0x4a9659, _0x30e2f7) {
  const _0x2ec10e = _0x4a9659.enumerateRanges("--x");
  if (_0x2ec10e == null || _0x2ec10e.length === 0) {
    return null;
  }
  _0x2ec10e.forEach((_0x3065ad, _0x3d2066) => {
    Memory.scan(_0x3065ad.base, _0x3065ad.size, _0x30e2f7, {
      onMatch: function (_0x4112ba, _0x37b296) {
        _kakakkkakkkkkkksanann(_0x4112ba);
      },
      onError: function (_0x3d0127) {},
      onComplete: function () {}
    });
  });
}
function fmap1p1ppa01nmalkaar(_0xcea523) {
  const _0x4db293 = Module.findExportByName(_0xcea523.name, "SSL_CTX_set_custom_verify");
  if (_0x4db293) {
    _kakakkkakkkkkkksanann(_0x4db293);
  } else {
    var _0x53c208 = null;
    var _0x1cca25 = Module.enumerateExports(_0xcea523.name);
    for (var _0x5d2148 = 0; _0x5d2148 < _0x1cca25.length; _0x5d2148++) {
      if (_0x1cca25[_0x5d2148].name.indexOf("set_custom_verify") !== -1) {
        _0x53c208 = _0x1cca25[_0x5d2148].address;
        _kakakkkakkkkkkksanann(_0x53c208);
        return;
      }
    }
    snska100110921jrn(_0xcea523, "01 ?? ?? B9 02 ?? ?? F9 C0 03 5F D6");
  }
}
var _21k1ka0hahaha = new Set();
function waitForModule(_0x26b510) {
  return new Promise(_0x12cba3 => {
    var _0x162ab6 = 0;
    var _0x51c0fb = Date.now();
    var _0x6e0857 = setInterval(() => {
      var _0x4f01b9 = Process.enumerateModules();
      var _0x28e351 = Date.now() - _0x51c0fb;
      for (var _0x1fba1c of _0x4f01b9) {
        if (_21k1ka0hahaha.has(_0x1fba1c.name)) {
          continue;
        }
        if (_0x1fba1c.name.indexOf(_0x26b510) != -1) {
          _21k1ka0hahaha.add(_0x1fba1c.name);
          clearInterval(_0x6e0857);
          _0x12cba3(_0x1fba1c);
        }
      }
      _0x162ab6++;
      if (_0x28e351 > 50000 || _0x162ab6 > 50000) {
        clearInterval(_0x6e0857);
      }
    }, 0);
  });
}
waitForModule(_0x7f80("xkhulvggp")).then(_0x5b9e19 => {
  fmap1p1ppa01nmalkaar(_0x5b9e19);
});
waitForModule(_0x7f80("qhklzf")).then(_0x28376d => {
  fmap1p1ppa01nmalkaar(_0x28376d);
});
waitForModule(_0x7f80("puxczxduzc")).then(_0x2aa70b => {
  fmap1p1ppa01nmalkaar(_0x2aa70b);
});
function classExists(_0x14fb1c) {
  var _0x1d0e62 = false;
  try {
    var _0x5cdff5 = Java.use(_0x14fb1c);
    _0x1d0e62 = true;
  } catch (_0x28a300) {}
  return _0x1d0e62;
}
function loadDexfile(_0x257bf8) {
  Java.perform(function () {
    Java.openClassFile(_0x257bf8).load();
  });
}
loadDexfile("/data/local/tmp/radar.dex");
function hasTrustManagerImpl() {
  return classExists("com.android.org.conscrypt.TrustManagerImpl");
}
function newArrayList() {
  var _0x3e7b54 = Java.use("java.util.ArrayList");
  return _0x3e7b54.$new();
}
function b0ringsslp() {
  try {
    if (classExists("org.chromium.net.CronetEngine$Builder")) {
      var _0x490b2f = Java.use("org.chromium.net.CronetEngine$Builder");
      _0x490b2f.enablePublicKeyPinningBypassForLocalTrustAnchors.implementation = function (_0xd7116c) {
        console.log("org.chromium.net.CronetEngine$Builder enablePublicKeyPinningBypassForLocalTrustAnchors was hooked!");
        return _0x490b2f.enablePublicKeyPinningBypassForLocalTrustAnchors.call(this, true);
      };
      _0x490b2f.addPublicKeyPins.implementation = function (_0x1073b7, _0x38058a, _0x278092, _0x3465d6) {
        console.log("org.chromium.net.CronetEngine$Builder addPublicKeyPins was hooked, hostName = " + _0x1073b7);
        return this;
      };
    }
  } catch (_0x2d400f) {
    console.log(_0x2d400f);
  }
}
function kaooqpjakk10a() {
  var _0x451665 = Java.use("android.webkit.WebViewClient");
  _0x451665.onReceivedSslError.implementation = function (_0x52ad90, _0x49e4e7, _0x3686a0) {
    console.log("WebViewClient onReceivedSslError was hooked!");
    _0x49e4e7.proceed();
    return;
  };
  _0x451665.onReceivedError.overload("android.webkit.WebView", "int", "java.lang.String", "java.lang.String").implementation = function (_0x591ff3, _0x426846, _0x5e08e8, _0x5d6601) {
    console.log("WebViewClient onReceivedError was hooked!");
    return;
  };
  _0x451665.onReceivedError.overload("android.webkit.WebView", "android.webkit.WebResourceRequest", "android.webkit.WebResourceError").implementation = function () {
    console.log("WebViewClient onReceivedError was hooked!");
    return;
  };
}
function klalo1mmmmal() {
  if (classExists("com.squareup.okhttp.CertificatePinner")) {
    var _0x4e0616 = Java.use("com.squareup.okhttp.CertificatePinner");
    var _0x33030b = _0x4e0616.check.overload("java.lang.String", "java.util.List");
    _0x33030b.implementation = function (_0x5fd39a, _0x24332d) {
      console.log("com.squareup.okhttp.CertificatePinner.check('java.lang.String', 'java.util.List') was hooked!");
    };
  }
  if (classExists("okhttp3.CertificatePinner")) {
    try {
      var _0x4f3d5c = Java.use("okhttp3.CertificatePinner");
      var _0x571191 = _0x4f3d5c.check.overload("java.lang.String", "java.util.List");
      _0x571191.implementation = function (_0x3bde97, _0x1e9ebc) {
        console.log("okhttp3.CertificatePinner.check('java.lang.String', 'java.util.List') was hooked!");
      };
    } catch (_0x17fe0f) {}
  }
  if (classExists("okhttp3.internal.tls.OkHostnameVerifier")) {
    try {
      var _0x552af6 = Java.use("okhttp3.internal.tls.OkHostnameVerifier");
      var _0x6b8303 = _0x552af6.verify.overload("java.lang.String", "javax.net.ssl.SSLSession");
      _0x6b8303.implementation = function (_0x19b01f, _0x136b4a) {
        console.log("okhttp3.internal.tls.OkHostnameVerifier.verify('java.lang.String', 'javax.net.ssl.SSLSession') was hooked!");
        return true;
      };
      var _0x3f4f69 = _0x552af6.verify.overload("java.lang.String", "java.security.cert.X509Certificate");
      _0x3f4f69.implementation = function (_0x13616e, _0x2c428e) {
        console.log("okhttp3.internal.tls.OkHostnameVerifier.verify('java.lang.String', 'java.security.cert.X509Certificate') was hooked!");
        return true;
      };
    } catch (_0x1356aa) {}
  }
  if (classExists("okhttp3.OkHttpClient$Builder")) {
    try {
      var _0x34db2f = Java.use("okhttp3.OkHttpClient$Builder");
      var _0x4a2840 = _0x34db2f.sslSocketFactory.overload("javax.net.ssl.SSLSocketFactory");
      _0x4a2840.implementation = function (_0x19e900) {
        var _0x3e8adc = _0x4a2840.call(this, Java.use("gz.justtrustme.Helper").getEmptySSLFactory());
        return _0x3e8adc;
      };
      var _0x269b50 = _0x34db2f.sslSocketFactory.overload("javax.net.ssl.SSLSocketFactory", "javax.net.ssl.X509TrustManager");
      _0x269b50.implementation = function (_0xf897d8, _0x3625ea) {
        var _0x580d42 = _0x269b50.call(this, Java.use("gz.justtrustme.Helper").getEmptySSLFactory(), _0x3625ea);
        return _0x580d42;
      };
    } catch (_0x3a8114) {}
  }
  if (classExists("com.squareup.okhttp.OkHttpClient")) {
    try {
      var _0x35baf2 = Java.use("com.squareup.okhttp.OkHttpClient");
      _0x35baf2.setCertificatePinner.implementation = function (_0x1043f9) {
        console.log("com.squareup.okhttp.setCertificatePinner was hooked!");
        return this;
      };
    } catch (_0x20f8fe) {
      console.log("com.squareup.okhttp not found");
    }
  }
}
function xmalk11o_JKKJKK() {
  if (classExists("org.xutils.http.RequestParams")) {
    var _0x1f8587 = Java.use("org.xutils.http.RequestParams");
    var _0xfc75b = _0x1f8587.setSslSocketFactory.overload("javax.net.ssl.SSLSocketFactory");
    _0xfc75b.implementation = function (_0x409240) {
      console.log("org.xutils.http.RequestParams.setSslSocketFactory('javax.net.ssl.SSLSocketFactory') was hooked!");
      var _0x858f68 = Java.use("gz.justtrustme.Helper");
      _0xfc75b.call(this, _0x858f68.getEmptySSLFactory());
    };
    var _0x5ddf96 = _0x1f8587.setHostnameVerifier.overload("javax.net.ssl.HostnameVerifier");
    _0x5ddf96.implementation = function (_0x40498a) {
      console.log("org.xutils.http.RequestParams.setHostnameVerifier('javax.net.ssl.HostnameVerifier') was hooked!");
      var _0x169c69 = Java.use("gz.justtrustme.ImSureItsLegitHostnameVerifier");
      _0x5ddf96.call(this, _0x169c69.$new());
    };
  }
}
function xnalkak11ll0ppi0000000ppp() {
  if (classExists("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier")) {
    var _0x1cef83 = Java.use("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier");
    var _0xa035f3 = _0x1cef83.verify.overload("java.lang.String", "[Ljava.lang.String;", "[Ljava.lang.String;", "boolean");
    _0xa035f3.implementation = function (_0x5c472c, _0x4a01ba, _0x28dcf3, _0xb72298) {
      console.log("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier.verify('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;', 'boolean') was hooked!");
    };
  }
}
function xxxxkakjakkkk() {
  if (!classExists("com.android.org.conscrypt.Platform")) {
    return;
  }
  var _0x9cef09 = Java.use("com.android.org.conscrypt.Platform");
  var _0x5ad300 = undefined;
  try {
    _0x5ad300 = _0x9cef09.checkServerTrusted.overload("javax.net.ssl.X509TrustManager", "[Ljava.security.cert.X509Certificate;", "java.lang.String", "com.android.org.conscrypt.OpenSSLEngineImpl");
  } catch (_0x51b937) {} finally {
    if (_0x5ad300) {
      _0x5ad300.implementation = function (_0x21ce75, _0x4abb8f, _0x1b5429, _0xdeaadd) {
        console.log("static void com.android.org.conscrypt.Platform.checkServerTrusted('javax.net.ssl.X509TrustManager', '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'com.android.org.conscrypt.OpenSSLEngineImpl') was hooked!");
      };
    }
  }
  var _0x4f6493 = undefined;
  try {
    _0x4f6493 = _0x9cef09.checkServerTrusted.overload("javax.net.ssl.X509TrustManager", "[Ljava.security.cert.X509Certificate;", "java.lang.String", "com.android.org.conscrypt.OpenSSLSocketImpl");
  } catch (_0x2b00de) {} finally {
    if (_0x4f6493) {
      _0x4f6493.implementation = function (_0x5827ca, _0x4736fc, _0x14382c, _0x1dfa9d) {
        console.log("static void com.android.org.conscrypt.Platform.checkServerTrusted('javax.net.ssl.X509TrustManager', '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'com.android.org.conscrypt.OpenSSLSocketImpl') was hooked!");
      };
    }
  }
  var _0x5c5d16 = undefined;
  try {
    _0x5c5d16 = _0x9cef09.checkServerTrusted.overload("javax.net.ssl.X509TrustManager", "[Ljava.security.cert.X509Certificate;", "java.lang.String", "com.android.org.conscrypt.AbstractConscryptSocket");
  } catch (_0x19aa7d) {} finally {
    if (_0x5c5d16) {
      _0x5c5d16.implementation = function (_0x5d6053, _0x3ccee8, _0x47a191, _0x111e42) {
        console.log("static void com.android.org.conscrypt.Platform.checkServerTrusted(javax.net.ssl.X509TrustManager,java.security.cert.X509Certificate[],java.lang.String,com.android.org.conscrypt.AbstractConscryptSocket) throws java.security.cert.CertificateException was hooked!");
      };
    }
  }
  var _0x5d876e = undefined;
  try {
    _0x5d876e = _0x9cef09.checkServerTrusted.overload("javax.net.ssl.X509TrustManager", "[Ljava.security.cert.X509Certificate;", "java.lang.String", "com.android.org.conscrypt.ConscryptEngine");
  } catch (_0x1b6f1f) {} finally {
    if (_0x5d876e) {
      _0x5d876e.implementation = function (_0x98ff07, _0x66035d, _0x5c73c9, _0x3c3e9b) {
        console.log("static void com.android.org.conscrypt.Platform.checkServerTrusted(javax.net.ssl.X509TrustManager,java.security.cert.X509Certificate[],java.lang.String,com.android.org.conscrypt.ConscryptEngine) throws java.security.cert.CertificateException was hooked!");
      };
    }
  }
}
function boringsslhook() {
  if (!classExists("appcelerator.https.PinningTrustManager")) {
    return;
  }
  var _0x1bcee0 = Java.use("appcelerator.https.PinningTrustManager");
  var _0x2c63fc = _0x1bcee0.checkServerTrusted.overload();
  _0x2c63fc.implementation = function () {};
}
function oooooooooxxxxxxxxx() {
  Java.perform(function () {
    var _0xfe4f7b = Java.use("gz.justtrustme.Helper");
    var _0x10dc0c = Java.use("org.apache.http.impl.client.DefaultHttpClient");
    var _0x12e1b4 = _0x10dc0c.$init.overload("org.apache.http.conn.ClientConnectionManager", "org.apache.http.params.HttpParams");
    _0x12e1b4.implementation = function (_0x1aa90e, _0x38199e) {
      var _0xa9f189 = _0x12e1b4.call(this, _0xfe4f7b.getCCM(_0x1aa90e, _0x38199e), _0x38199e);
      console.log("org.apache.http.impl.client.DefaultHttpClient.$init('org.apache.http.conn.ClientConnectionManager', 'org.apache.http.params.HttpParams') was hooked!");
      return _0xa9f189;
    };
    var _0x36397a = _0x10dc0c.$init.overload();
    _0x36397a.implementation = function () {
      var _0x2edf6f = _0x12e1b4.call(this, _0xfe4f7b.getSCCM(), null);
      console.log("org.apache.http.impl.client.DefaultHttpClient.$init() was hooked!");
      return _0x2edf6f;
    };
    var _0x34ab9b = _0x10dc0c.$init.overload("org.apache.http.params.HttpParams");
    _0x34ab9b.implementation = function (_0x1b67f7) {
      var _0x3d227e = _0x12e1b4.call(this, _0xfe4f7b.getSCCM(), _0x1b67f7);
      console.log("org.apache.http.impl.client.DefaultHttpClient.$init('org.apache.http.params.HttpParams') was hooked!");
      return _0x3d227e;
    };
    var _0x57ce54 = Java.use("android.net.http.X509TrustManagerExtensions");
    var _0x238160 = _0x57ce54.checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String", "java.lang.String");
    _0x238160.implementation = function (_0x165b3f, _0x522062, _0x5d6ecf) {
      console.log("android.net.http.X509TrustManagerExtensions.checkServerTrusted('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String') was hooked!");
      return Java.use("java.util.Arrays$ArrayList").$new(_0x165b3f);
    };
    var _0x47a306 = Java.use("android.security.net.config.NetworkSecurityTrustManager");
    var _0x53ef29 = _0x47a306.checkPins.overload("java.util.List");
    _0x53ef29.implementation = function (_0x1c6230) {
      console.log("android.security.net.config.NetworkSecurityTrustManager.checkPins('java.util.List') was hooked!");
    };
    var _0xbebbc1 = Java.use("org.apache.http.conn.ssl.SSLSocketFactory");
    var _0x2f8fd7 = _0xbebbc1.$init.overload("java.lang.String", "java.security.KeyStore", "java.lang.String", "java.security.KeyStore", "java.security.SecureRandom", "org.apache.http.conn.scheme.HostNameResolver");
    _0x2f8fd7.implementation = function (_0xc06abb, _0x2a818e, _0x9f3d86, _0x18936c, _0x33bbbe, _0x3aa4e8) {
      var _0x2f5065 = _0x2f8fd7.call(this, _0xc06abb, _0x2a818e, _0x9f3d86, _0x18936c, _0x33bbbe, _0x3aa4e8);
      console.log("org.apache.http.conn.ssl.SSLSocketFactory.$init('java.lang.String', 'java.security.KeyStore', 'java.lang.String', 'java.security.KeyStore', 'java.security.SecureRandom', 'org.apache.http.conn.scheme.HostNameResolver') was hooked!");
      if (_0xfe4f7b.reInitSSLSocketFactory(this, _0xc06abb, _0x2a818e, _0x9f3d86, _0x18936c, _0x33bbbe, _0x3aa4e8)) {
        console.log("替换trustmanagers参数成功!");
      } else {
        console.log("替换trustmanagers参数失败!");
      }
      return _0x2f5065;
    };
    var _0x24254 = _0xbebbc1.getSocketFactory.overload();
    var _0x15adb1 = _0xbebbc1.$init.overload();
    _0x24254.implementation = function () {
      console.log("org.apache.http.conn.ssl.SSLSocketFactory.getSocketFactory() was hooked!");
      return _0xbebbc1.$new();
    };
    var _0x20ad71 = _0xbebbc1.isSecure.overload("java.net.Socket");
    _0x20ad71.implementation = function (_0x1e1b1c) {
      console.log("org.apache.http.conn.ssl.SSLSocketFactory.isSecure('java.net.Socket') was hooked!");
      return true;
    };
    var _0x4297ea = Java.use("javax.net.ssl.TrustManagerFactory");
    var _0x226d96 = _0x4297ea.getTrustManagers.overload();
    _0x226d96.implementation = function () {
      var _0x38f5fd = _0x226d96.call(this);
      console.log("javax.net.ssl.TrustManagerFactory.getTrustManagers() was hooked!");
      return _0xfe4f7b.replaceGetTrustManagers(this, _0x38f5fd);
    };
    var _0x57abb3 = Java.use("javax.net.ssl.HttpsURLConnection");
    var _0x2cf171 = _0x57abb3.setDefaultHostnameVerifier.overload("javax.net.ssl.HostnameVerifier");
    _0x2cf171.implementation = function (_0x155e79) {
      console.log("javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier('javax.net.ssl.HostnameVerifier') was hooked!");
    };
    var _0x53216d = _0x57abb3.setHostnameVerifier.overload("javax.net.ssl.HostnameVerifier");
    _0x53216d.implementation = function (_0x13c153) {
      console.log("javax.net.ssl.HttpsURLConnection.setHostnameVerifier('javax.net.ssl.HostnameVerifier') was hooked!");
    };
    var _0x54f808 = _0x57abb3.setSSLSocketFactory.overload("javax.net.ssl.SSLSocketFactory");
    _0x54f808.implementation = function (_0x34f537) {
      console.log("javax.net.ssl.SSLSocketFactory.setSSLSocketFactory('javax.net.ssl.SSLSocketFactory') was hooked!");
    };
    var _0x2990d5 = Java.use("javax.net.ssl.X509TrustManager");
    var _0x1df7e4 = Java.registerClass({
      implements: [_0x2990d5],
      methods: {
        checkClientTrusted(_0x244dbe, _0x26ed11) {},
        checkServerTrusted(_0x457d68, _0x528e41) {},
        getAcceptedIssuers() {
          return [];
        }
      },
      name: "com.leftenter.douyin"
    });
    var _0x5bcc89 = [_0x1df7e4.$new()];
    var _0x3e8587 = Java.use("javax.net.ssl.SSLContext");
    var _0xe8ba6 = _0x3e8587.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom");
    _0xe8ba6.implementation = function (_0x282d1f, _0xcd29ba, _0x35d8af) {
      _0xe8ba6.call(this, _0x282d1f, _0x5bcc89, _0x35d8af);
      console.log("javax.net.ssl.SSLContext.init('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom') was hooked!");
    };
    var _0x5d0835 = Java.use("android.app.Application");
    var _0x46fcea = _0x5d0835.attach.overload("android.content.Context");
    _0x46fcea.implementation = function (_0x4581cb) {
      _0x46fcea.call(this, _0x4581cb);
      var _0x364542 = _0x4581cb.getClassLoader();
    };
    if (hasTrustManagerImpl()) {
      var _0x1c5415 = Java.use("com.android.org.conscrypt.TrustManagerImpl");
      var _0x510ef9 = undefined;
      try {
        _0x510ef9 = _0x1c5415.checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String", "java.lang.String");
      } catch (_0x1c7533) {} finally {
        if (_0x510ef9) {
          _0x510ef9.implementation = function (_0x55e426, _0x2a4e93, _0xe9063c) {
            console.log("com.android.org.conscrypt.TrustManagerImpl.checkServerTrusted('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String') was hooked!");
            return newArrayList();
          };
        }
      }
      var _0x1d91cf = undefined;
      try {
        _0x1d91cf = _0x1c5415.checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String", "javax.net.ssl.SSLSession");
      } catch (_0x3064d5) {} finally {
        if (_0x1d91cf) {
          _0x1d91cf.implementation = function (_0x2be686, _0x391c01, _0x1f35ed) {
            console.log("com.android.org.conscrypt.TrustManagerImpl.checkServerTrusted('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'javax.net.ssl.SSLSession') was hooked!");
            return newArrayList();
          };
        }
      }
      var _0x3c4921 = undefined;
      try {
        _0x3c4921 = _0x1c5415.checkTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String", "javax.net.ssl.SSLSession", "javax.net.ssl.SSLParameters", "boolean");
      } catch (_0x2f7336) {} finally {
        if (_0x3c4921) {
          _0x3c4921.implementation = function (_0x17cf2c, _0x533000, _0x5f2006, _0x4cecde, _0x2dfc97) {
            console.log("com.android.org.conscrypt.TrustManagerImpl.checkTrusted('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'javax.net.ssl.SSLSession', 'javax.net.ssl.SSLParameters', 'boolean') was hooked!");
            return newArrayList();
          };
        }
      }
      var _0x438971 = undefined;
      try {
        _0x438971 = _0x1c5415.checkTrusted.overload("[Ljava.security.cert.X509Certificate;", "[B", "[B", "java.lang.String", "java.lang.String", "boolean");
      } catch (_0x2c79ec) {} finally {
        if (_0x438971) {
          _0x438971.implementation = function (_0x21b8e7, _0xcf806b, _0x339837, _0x1e1c5c, _0x4523ff, _0x3e0c3c) {
            console.log("private java.util.List com.android.org.conscrypt.TrustManagerImpl.checkTrusted(java.security.cert.X509Certificate[],byte[],byte[],java.lang.String,java.lang.String,boolean) throws java.security.cert.CertificateException was hooked!");
            return newArrayList();
          };
        }
      }
      try {
        var _0x1e249b = Java.use("java.util.ArrayList");
        if (_0x1c5415.checkTrustedRecursive) {
          _0x1c5415.checkTrustedRecursive.implementation = function (_0x102419, _0x34e76f, _0x3a196a, _0x44b509, _0x157525, _0x2ad3cd) {
            var _0x45b5e9 = _0x1e249b.$new();
            return _0x45b5e9;
          };
        }
      } catch (_0x1c3538) {}
    }
    b0ringsslp();
    kaooqpjakk10a();
    klalo1mmmmal();
    xmalk11o_JKKJKK();
    xnalkak11ll0ppi0000000ppp();
    xxxxkakjakkkk();
    boringsslhook();
  });
}
function jte() {
  Java.perform(function () {
    var _0x2cbffd = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
    var _0x11461c = _0x2cbffd.getPackageName();
    console.log("Package name: " + _0x11461c);
    if (!_0x11461c.startsWith(_0x7f80("qkn.gg.olmhkum"))) {
      setTimeout(oooooooooxxxxxxxxx, 0);
    }
  });
}
setTimeout(jte, 2000);