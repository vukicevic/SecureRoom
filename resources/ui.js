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

    document.getElementById("sidebarToggle").addEventListener("click", UI.toggleSidebar());

    document.getElementById("message").addEventListener("keyup", function (e) { e.which === 13 && document.getElementById("send").click() });
    document.getElementById("send").addEventListener("click", function () { var d = document.getElementById("message"); if (d.value) secureroom.sendMessage(d.value); d.value = "" });
    
    document.getElementById("room").addEventListener("click", function () { window.prompt('Copy the URL of this SecureRoom: CTRL-C then Enter', window.location) });

    document.getElementById("generate").addEventListener("click", function () { if (!this.disabled) { secureroom.generateUser(document.getElementById("nickname").value, document.getElementById("keysize").value); UI.addWelcome("progress")() } });
    document.getElementById("nickname").addEventListener("keyup", function (e) { var d = document.getElementById("generate"); d.disabled = this.value.length < 3; e.which === 13 && d.click() });
    document.getElementById("nickname").focus();
  },

  toggleSidebar: function() {
    var ctrl = document.getElementById("sidebarToggle"),
        elem = document.getElementById("sidebar");

    return function () {
      ctrl.classList.toggle("open");
      elem.classList.toggle("open");
    };
  },

  toggleUser: function (user, ctrl) {
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
      elem.style.height = (ctrl.classList.toggle("selected")) ? elem.scrollHeight + "px" : 0;
    };
  },

  toggleRoom: function () {
    document.getElementById("room").textContent = secureroom.config.room;
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

  addUser: function (user) {
    if (!document.getElementById("alert-" + user.id)) {
      var container = document.getElementById("content"),
          build     = TemplateEngine("template-key-alert"),
          content   = {};

      content.id   = PrintUtil.text(user.id);
      content.time = PrintUtil.time(Math.round(Date.now() / 1000));
      content.name = PrintUtil.text(user.name);
      content.info = UI.buildKeyInfo(user);

      container.insertAdjacentHTML("beforeend", build(content));

      UI.addUserListeners(document.getElementById("alert-" + user.id), user);
      window.scrollTo(0, document.body.offsetHeight);
    }
  },

  addUserListeners: function (elem, user) {
    var a = elem.getElementsByTagName("button").item(0),
        r = elem.getElementsByTagName("button").item(1),
        p = elem.querySelector(".join"),
        d = UI.removeContent(a.parentNode);

    a.addEventListener("click", function () {
      elem.classList.add("event");
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
  },

  addKeychainListeners: function (elem, user) {
    var b1 = elem.getElementsByTagName("span").item(0),
        b2 = elem.getElementsByTagName("span").item(1);

    b1.addEventListener("click", UI.toggleUser(user, b1));
    b2.addEventListener("click", UI.toggleExport(elem.querySelector(".export"), b2));
  },

  addWelcome: function (type) {
    var container = document.getElementById("welcome");

    return function() {
      while (container.firstChild)
        container.removeChild(container.firstChild);

      switch (type) {
        case "distribute":
          UI.createRoom();
          container.insertAdjacentHTML("beforeend", "<h1>Success!</h1><h3><em>Keys generated.</em></h3><div class='info'>" + UI.buildKeyInfo(secureroom.user) + "</div><button>Connect &amp; Distribute</button>");
          container.querySelector("button").addEventListener("click", function () {
            secureroom.connectToServer();
            UI.addWelcome("progress")();
          });
          UI.addMyUser();
          UI.toggleRoom();
          break;
        case "progress":
          container.insertAdjacentHTML("beforeend", "<div class='loading'></div>");
          break;
        case "connect":
          container.style.display = "none";
          container.parentNode.style.backgroundColor = "white";
          secureroom.channel.sendUser(secureroom.user);
        case "disconnect":
          document.getElementById("content").insertAdjacentHTML("beforeend", "<li class='event'><div class='time'>" + PrintUtil.time(Math.round(Date.now()/1000)) + "</div><p>" + type.charAt(0).toUpperCase() + type.slice(1) + "ed.</p></li>");
          break;
      }
    }
  },

  addMyUser: function () {
    document.getElementById("my-name").textContent = PrintUtil.text(secureroom.user.name);

    var e1 = document.getElementById("my-private-key"),
        e2 = document.getElementById("my-public-key"),
        e3 = document.getElementById("my-key-info"),
        b1 = document.getElementById("my-private-key-toggle"),
        b2 = document.getElementById("my-public-key-toggle"),
        b3 = document.getElementById("my-key-info-toggle"),
        kh = ExportUtil();

    e1.textContent = kh.privateGpg(secureroom.user);
    e2.textContent = kh.publicGpg(secureroom.user);
    e3.insertAdjacentHTML("beforeend", UI.buildKeyInfo(secureroom.user));

    b1.addEventListener("click", UI.toggleExport(e1.parentNode, b1));
    b2.addEventListener("click", UI.toggleExport(e2.parentNode, b2));
    b3.addEventListener("click", UI.toggleExport(e3, b3));
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