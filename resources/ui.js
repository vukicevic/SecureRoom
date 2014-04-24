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

    secureroom.config.room   = getUrlParam("room");
    secureroom.config.server = getUrlParam("server") || "wss://princip.secureroom.net/ws";

    UI.initVars();
    UI.initForm();
    UI.initSidebar();
  },

  initSidebar: function() {
    var ctrl = document.getElementById("sidebarToggle"),
        elem = document.getElementById("sidebar");

    ctrl.addEventListener("click", function () {
      ctrl.classList.toggle("open");
      elem.classList.toggle("open");
    });
  },

  initVars: function () {
    document.getElementById("server").textContent = secureroom.config.server;
    document.getElementById("room").textContent   = secureroom.config.room;
  },

  initForm: function () {   
    var b = document.getElementById("generate"),
        i = document.getElementById("nickname");

    b.addEventListener("click", function () { 
      if (!this.disabled) { 
        secureroom.generateUser(i.value, document.getElementById("keysize").value); 
        UI.addProgress();
      }
    });
    
    i.addEventListener("keyup", function (e) { 
      b.disabled = this.value.length < 3; 
      if (e.which === 13) b.click();
    });

    i.focus();
  },

  initRoom: function () {
    if (secureroom.config.room === "") {
      var opts, path;

      secureroom.config.room = secureroom.user.id.substr(-5);
      
      opts = window.location.search ? window.location.search + "&room=" : "?room=";
      path = window.location.pathname + opts + secureroom.config.room;
      
      window.history.replaceState({}, "SecureRoom", path);
    }
  },

  initInput: function() {
    var m = document.getElementById("message"),
        s = document.getElementById("send");

    m.addEventListener("keyup", function (e) { 
      if (e.which === 13)
        s.click();
    });
    
    s.addEventListener("click", function () { 
      if (m.value !== "") {
        secureroom.sendMessage(m.value);
        m.value = "";
      }
    });
  },

  toggleUser: function (user, ctrl) {
    ctrl.addEventListener("click", function () {
      if (user.status === "active") {
        ctrl.classList.add("inactive");
        ctrl.textContent = "DISABLED";
        user.status = "disabled";
      } else {
        ctrl.classList.remove("inactive");
        ctrl.textContent = "ACTIVE";
        user.status = "active";
      }
    });
  },

  toggleExport: function (elem, ctrl) {
    ctrl.addEventListener("click", function () {
      elem.style.height = (ctrl.classList.toggle("selected")) ? elem.scrollHeight + "px" : 0;
    });
  },

  removeContent: function (elem, ctrl) {
    elem.style.height = elem.scrollHeight + "px";
    ctrl.addEventListener("click", function() {
      elem.style.height = "0px";
      while (elem.firstChild) elem.removeChild(elem.firstChild);  
    });
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

      UI.toggleExport(container.lastChild.querySelector(".info"), container.lastChild.querySelector(".time"));

      window.scrollTo(0, document.body.offsetHeight);
    }
  },

  addUser: function (user) {
    if (!document.getElementById("alert-" + user.id)) {
      var container = document.getElementById("content"),
          build     = TemplateEngine("template-key-alert"),
          content   = {};

      content.id   = PrintUtil.text(user.id);
      content.time = PrintUtil.time(Math.round(Date.now() / 1000));
      content.name = PrintUtil.text(user.name);
      content.info = UI.buildKeyInfo(user.master) + UI.buildKeyInfo(user.ephemeral);

      container.insertAdjacentHTML("beforeend", build(content));

      window.scrollTo(0, document.body.offsetHeight);

      UI.addUserListeners(container.lastChild, user);
    }
  },

  addUserListeners: function (elem, user) {
    var a = elem.getElementsByTagName("button").item(0),
        r = elem.getElementsByTagName("button").item(1),
        p = elem.querySelector(".join");

    a.addEventListener("click", function () {
      elem.classList.remove("alert");
      elem.classList.add("event");
      p.classList.add("accept");

      user.status = "active";

      UI.addToChain(user);
      secureroom.channel.sendUser(secureroom.user);
    });

    r.addEventListener("click", function () {
      elem.classList.remove("alert");
      elem.classList.add("warning");
      p.classList.add("reject");

      user.status = "rejected";
    });

    UI.removeContent(a.parentNode, a);
    UI.removeContent(r.parentNode, r);
  },

  buildRecipientList: function(message) {
    return message.recipients.map(function(id) {
      var recipient = (secureroom.user.ephemeral.id === id) ? secureroom.user : secureroom.vault.findUser(id);
      return (typeof recipient !== "undefined") ? (recipient.status !== "rejected") ? PrintUtil.text(recipient.name) : "REJECTED" : "UNKNOWN";
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

  buildKeyInfo: function (key) {
    var build = TemplateEngine("template-key-info"),
        content = {};

    content.type = key.isMaster() ? "Master Signing Key" : "Ephemeral Encryption Key";
    content.id   = PrintUtil.id(key.id);
    content.size = PrintUtil.number(key.size);
    content.date = PrintUtil.date(key.created);

    return build(content);
  },

  addToChain: function (user) {
    var chain    = document.getElementById("keychain"),
        build    = TemplateEngine("template-key-chain"),
        content  = {},
        bn, da;

    content.id   = PrintUtil.text(user.id);
    content.name = PrintUtil.text(user.name);
    content.info = UI.buildKeyInfo(user.master) + UI.buildKeyInfo(user.ephemeral);
    content.data = ExportUtil().publicGpg(user);

    chain.insertAdjacentHTML("beforeend", build(content));
    
    bn = chain.lastChild.getElementsByTagName("span"),
    da = chain.lastChild.querySelectorAll("div.info");

    UI.toggleExport(da.item(0), bn.item(0));
    UI.toggleExport(da.item(1), bn.item(1));
    UI.toggleUser(user, bn.item(2));
  },

  addDistribute: function () {
    var container = document.getElementById("welcome");
    
    while (container.firstChild) 
        container.removeChild(container.firstChild);
    
    container.insertAdjacentHTML("beforeend", "<h1>Success!</h1><h3><em>Key <b>" + PrintUtil.id(secureroom.user.id) + "</b> generated.</em></h3><button>Connect &amp; Distribute</button>");
    
    container.querySelector("button").addEventListener("click", function () {
      secureroom.connectToServer();
      UI.addProgress();
    });

    UI.initRoom();
    UI.initVars();
    UI.addMyUser();
  },

  addProgress: function() {
    var container = document.getElementById("welcome");
    
    while (container.firstChild) 
        container.removeChild(container.firstChild);

    container.insertAdjacentHTML("beforeend", "<div class='loading'></div>");
  },

  addConnect: function() {
    var action    = "Disconnected",
        container = document.getElementById("welcome");
    
    while (container.firstChild) 
      container.removeChild(container.firstChild);
    
    if (secureroom.channel.isConnected()) {
      action = "Connected";
      secureroom.channel.sendUser(secureroom.user);
      UI.initInput();
    }

    container.parentNode.style.backgroundColor = "white";
    container.style.display = "none";

    document.getElementById("content").insertAdjacentHTML("beforeend", "<li class='event'><div class='time'>" + PrintUtil.time(Math.round(Date.now()/1000)) + "</div><p>" + action + ".</p></li>");
  },

  addMyUser: function () {
    var e1 = document.getElementById("my-private-key"),
        e2 = document.getElementById("my-public-key"),
        e3 = document.getElementById("my-key-info"),
        kh = ExportUtil();

    e1.textContent = kh.privateGpg(secureroom.user);
    e2.textContent = kh.publicGpg(secureroom.user);
    e3.insertAdjacentHTML("beforeend", UI.buildKeyInfo(secureroom.user.master) + UI.buildKeyInfo(secureroom.user.ephemeral));

    UI.toggleExport(e1.parentNode, document.getElementById("my-private-key-toggle"));
    UI.toggleExport(e2.parentNode, document.getElementById("my-public-key-toggle"));
    UI.toggleExport(e3, document.getElementById("my-key-info-toggle"));

    document.getElementById("my-name").textContent = PrintUtil.text(secureroom.user.name);
    document.getElementById("my-controls").classList.remove("hidden");
  }
}