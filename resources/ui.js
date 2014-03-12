function TemplateEngine(templ) {
  if (typeof templ !== "undefined")
    templ = document.getElementById(templ).innerHTML.replace(/\n|\r/g, "").replace(/>\s+</g, "><").trim();

  return function compile(data, template) {
    var match, tpart, i;

    if (typeof template === "undefined")
      template = templ;

    while (match = /\{\{#([a-zA-Z]+)\}\}(.+)\{\{\/\1\}\}/g.exec(template)) {
      for (tpart = "", i = 0; i < data[match[1]].length; i++)
        tpart += compile(data[match[1]][i], match[2]);

      template = template.split(match[0]).join(tpart);
      delete data[match[1]];
    }

    for (match in data)
      template = template.split("{{" + match + "}}").join(data[match]);

    return template;
  }
}

var UI = {
  init: function() {
    var getUrlParam = function(name) {
      var match = new RegExp("[?&]" + name + "=([^&]*)").exec(window.location.search);
      return (match) ? decodeURIComponent(match[1].replace(/\+/g, " ")) : "";
    }

    secureroom.config.room = window.location.pathname.substr(window.location.pathname.lastIndexOf("/")+1);
    if (secureroom.config.room === "index.html") {
      secureroom.config.room = getUrlParam("room");
    }

    secureroom.config.server = getUrlParam("server") ? "wss://"+getUrlParam("server")+":443/ws/" : "wss://"+document.location.host+":443/ws/";

    UI.toggleRoom();

    document.getElementById("keychainToggle").addEventListener("click", UI.toggleKeychain());
    document.getElementById("settingsToggle").addEventListener("click", UI.toggleSettings());

    document.getElementById("asymsize").addEventListener("click", function (e) { if (e.target.tagName.toLowerCase() === "span") secureroom.config.key.size = UI.toggleSize(e.target) });

    document.getElementById("message").addEventListener("keyup", function (e) { e.keyCode === 13 && document.getElementById("send").click() });
    document.getElementById("send").addEventListener("click", function (e) { var d = document.getElementById("message"); if (d.value) secureroom.sendMessage(d.value); d.value = "" });

    document.getElementById("serverurl").textContent = secureroom.config.server + secureroom.config.room;
    document.getElementById("nickname").focus();
  },

  toggleKeychain: function() {
    var ctrl = document.getElementById("keychainToggle"),
        elem = document.getElementById("keychain");

    return function (close) {
      if (ctrl.classList.contains("open") || close === "close") {
        ctrl.classList.remove("open");
        elem.style.bottom = "-" + (elem.clientHeight + 5) + "px";

        var node;
        while ((node = elem.querySelector(".export:not(.hidden)"))) node.classList.add("hidden");
        while ((node = elem.querySelector(".selected"))) node.classList.remove("selected");
      } else {
        ctrl.classList.add("open");
        elem.style.bottom = (ctrl.clientHeight - 5) + "px";
      }
    };
  },

  toggleSettings: function() {
    var ctrl = document.getElementById("settingsToggle"),
        elem = document.getElementById("settings");

    return function (close) {
      if (ctrl.classList.contains("open") || close === "close") {
        ctrl.classList.remove("open");
        elem.style.marginTop = "-" + (elem.clientHeight - ctrl.clientHeight) + "px";
        window.scrollTo(0, document.body.offsetHeight);
      } else {
        ctrl.classList.add("open");
        elem.style.marginTop = ctrl.clientHeight + "px";
        window.scrollTo(0, 0);
      }
    };
  },

  toggleKey: function (user, ctrl) {
    return function () {
      if (user.status === "active") {
        ctrl.classList.add("inactive");
        ctrl.textContent = "DISABLED";
        user.status = "disabled";
      } else {
        ctrl.classList.remove("inactive");
        ctrl.textContent = "ACTIVE";
        user.status = "active";
      }
    };
  },

  toggleExport: function (elem, ctrl) {
    return function () {
      if (elem.classList.contains("hidden")) {
        elem.classList.remove("hidden");
        ctrl.classList.add("selected");
      } else {
        elem.classList.add("hidden");
        ctrl.classList.remove("selected");
      }

      elem.style.left = (elem.parentNode.getBoundingClientRect().left - 1) + "px";
      elem.style.top  = "-" + (elem.offsetHeight - (elem.parentNode.getBoundingClientRect().top - elem.parentNode.parentNode.getBoundingClientRect().top)) + "px";
    };
  },

  toggleSize: function (elem) {
    elem.parentNode.querySelector(".selected").classList.remove("selected");
    elem.classList.add("selected");
    return parseInt(elem.textContent);
  },

  toggleInput: function (close) {
    document.getElementById("input").style.bottom = (close) ? "-2.3125em" : "0em";
  },

  toggleRoom: function () {
    document.getElementById("room").textContent = "Room: " + secureroom.config.room;
  },

  toggleHeight: function (elem) {
    var height = elem.offsetHeight;

    if (elem.classList.contains("hidden-height")) {
      elem.style.height = "0px";
      elem.classList.remove("hidden-height");
    } else {
      elem.style.height = height + "px";
    }

    return function () {
      elem.style.height = (elem.style.height == "0px") ? height + "px" : "0px";
    }
  },

  removeContent: function (elem) {
    elem.style.height = elem.offsetHeight + "px";

    return function () {
      elem.style.height = "0px";
      while (elem.firstChild) elem.removeChild(elem.firstChild);
    }
  },

  disableSettings: function (setting) {
    var parent = document.getElementById(setting), node;

    switch (setting) {
      case "asymsize":
        while ((node = parent.querySelector("span:not(.selected)"))) parent.removeChild(node);
        break;
      case "serverurl":
        parent.classList.add("selected");
        parent.contentEditable = false;
        break;
    }
  },

  addMessage: function (message) {
    if (message.verified) {
      var container = document.getElementById("content"),
          build = TemplateEngine("template-message"),
          content = {};

      content.time    = PrintUtil.time(message.sendtime+message.timediff);
      content.sender  = PrintUtil.text((message.sender !== secureroom.user.id) ? secureroom.vault.findUser(message.sender).name : secureroom.user.name);
      content.message = PrintUtil.text(message.plaintext);
      content.info    = UI.buildMsgInfo(message);
      content.class   = (message.verified) ? "" : " warning";

      container.insertAdjacentHTML("beforeend", build(content));

      UI.addMessageListeners(container.lastChild);
      window.scrollTo(0, document.body.offsetHeight);
    }
  },

  addMessageListeners: function (elem) {
    elem.addEventListener("click", UI.toggleHeight(elem.querySelector(".info")));
  },

  addKey: function (user) {
    if (!document.getElementById("alert-" + user.id)) {
      var container = document.getElementById("content"),
          build     = TemplateEngine("template-key-alert"),
          content   = {};

      content.id   = PrintUtil.text(user.id);
      content.time = PrintUtil.time(Math.round(Date.now() / 1000));
      content.name = PrintUtil.text(user.name);
      content.info = UI.buildKeyInfo(user);

      container.insertAdjacentHTML("beforeend", build(content));

      UI.addKeyListeners(document.getElementById("alert-" + user.id), user);
      window.scrollTo(0, document.body.offsetHeight);
    }
  },

  addKeyListeners: function (elem, user) {
    var a = elem.getElementsByTagName("button").item(0),
        r = elem.getElementsByTagName("button").item(1),
        p = elem.querySelector(".join"),
        d = UI.removeContent(a.parentNode);

    a.addEventListener("click", function () {
      p.classList.add("accept");

      user.status = "active";

      UI.addToChain(user);
      secureroom.channel.sendUser(secureroom.user);
    });

    a.addEventListener("click", d);

    r.addEventListener("click", function () {
      elem.classList.add("warning");
      p.classList.add("reject");

      user.status = "rejected";
    });

    r.addEventListener("click", d);
  },

  buildRecipientList: function(message) {
    return message.recipients.map(function(id) {
      var recipient = (secureroom.user.ephemeral.id === id) ? secureroom.user : secureroom.vault.findUser(id);
      return (typeof recipient !== "undefined") ? (recipient.status !== "rejected") ? PrintUtil.text(recipient.name) : "Rejected" : "Unknown";
    }).join(", ");
  },

  buildMsgInfo: function (message) {
    var build = TemplateEngine("template-message-info"),
        content = {info: []};

    content.info.push({term: "Author", data: PrintUtil.id(message.sender)});
    content.info.push({term: "Cipher", data: "AES-CFB 128-bit"});
    content.info.push({term: "Delay", data: message.timediff + " sec"});
    content.info.push({term: "Recipients", data: this.buildRecipientList(message)});

    return build(content);
  },

  buildKeyInfo: function (user) {
    var build = TemplateEngine("template-key-info"),
        content = {};

    content.sid   = PrintUtil.id(user.id);
    content.ssize = PrintUtil.number(user.master.size);
    content.sdate = PrintUtil.date(user.master.created);

    return build(content);
  },

  addToChain: function (user) {
    var container = document.getElementById("keychain"),
        build = TemplateEngine("template-key-chain"),
        content = {};

    content.id     = PrintUtil.text(user.id);
    content.name   = PrintUtil.text(user.name);
    content.info   = UI.buildKeyInfo(user);
    content.data   = ExportUtil().publicGpg(user);

    container.insertAdjacentHTML("beforeend", build(content));
    UI.addKeychainListeners(container.lastChild, user);

    UI.toggleKeychain()("close");
  },

  addKeychainListeners: function (elem, user) {
    var b1 = elem.getElementsByTagName("span").item(0),
        b2 = elem.getElementsByTagName("span").item(1);

    b1.addEventListener("click", UI.toggleKey(user, b1));
    b2.addEventListener("click", UI.toggleExport(elem.querySelector(".export"), b2));
  },

  addWelcome: function (type) {
    var container = document.getElementById("welcome");

    while (container.firstChild)
      container.removeChild(container.firstChild);

    switch (type) {
      case "distribute":
        container.insertAdjacentHTML("beforeend", "<p>Your keys have been generated.</p><div class='info'>" + UI.buildKeyInfo(secureroom.user) + "</div><button>Connect &amp; Distribute</button>");
        container.querySelector("button").addEventListener("click", function () {
          secureroom.connectToServer();
          UI.addWelcome("progress");
          UI.disableSettings("serverurl")
        });
        UI.addMyKey();
        break;
      case "progress":
        container.insertAdjacentHTML("beforeend", "<div class='loading'></div>");
        break;
      case "connect":
        secureroom.channel.sendUser(secureroom.user);
      case "disconnect":
        container.insertAdjacentHTML("beforeend", "<div class='time'>" + PrintUtil.time(Math.round(Date.now()/1000)) + "</div><p>" + type.charAt(0).toUpperCase() + type.slice(1) + "ed.</p>");
        break;
    }
  },

  addMyKey: function () {
    document.getElementById("myname").textContent = PrintUtil.text(secureroom.user.name);
    document.getElementById("myinfo").insertAdjacentHTML("beforeend", UI.buildKeyInfo(secureroom.user));

    var my = document.getElementById("mykey"),
        e1 = my.getElementsByTagName("textarea").item(0),
        e2 = my.getElementsByTagName("textarea").item(1),
        b1 = my.getElementsByTagName("span").item(0),
        b2 = my.getElementsByTagName("span").item(1),
        kh = ExportUtil();

    e1.textContent = kh.privateGpg(secureroom.user);
    e2.textContent = kh.publicGpg(secureroom.user);

    b1.addEventListener("click", UI.toggleExport(e1.parentNode, b1));
    b2.addEventListener("click", UI.toggleExport(e2.parentNode, b2));
  },

  createRoom: function () {
    if (secureroom.config.room === "") {
      var opts, path;

      secureroom.config.room = secureroom.user.id.substr(-5);
      
      opts = window.location.search ? window.location.search + "&room=" : "?room=";
      path = (window.location.pathname.indexOf("index.html") < 0) ? window.location.pathname + secureroom.config.room : window.location.pathname + opts + secureroom.config.room;
      
      window.history.replaceState({}, "SecureRoom", path);
    }
  }
}