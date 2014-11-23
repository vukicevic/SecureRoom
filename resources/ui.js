var UI = {
  TemplateEngine: function (templ) {
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
  },

  init: function (app) {
    var getUrlParam = function (name) {
      var match = new RegExp("[?&]" + name + "=([^&]*)").exec(window.location.search);
      return (match) ? decodeURIComponent(match[1].replace(/\+/g, " ")) : "";
    }

    UI.app = app;

    UI.app.config.room   = getUrlParam("room");
    UI.app.config.server = getUrlParam("server") || "wss://princip.secureroom.net/ws";

    UI.initVars();
    UI.initForm();
    UI.initSidebar();
  },

  initSidebar: function () {
    var ctrl = document.getElementById("sidebarToggle"),
        elem = document.getElementById("sidebar");

    ctrl.addEventListener("click", function () {
      ctrl.classList.toggle("open");
      elem.classList.toggle("open");
    });
  },

  initVars: function () {
    document.getElementById("server").textContent = UI.app.config.server;
    document.getElementById("room").textContent   = UI.app.config.room;
  },

  initForm: function () {   
    var b = document.getElementById("generate"),
        i = document.getElementById("nickname");

    b.disabled = true;

    b.addEventListener("click", function () { 
      if (!this.disabled) { 
        UI.app.generateUser(i.value, document.getElementById("keysize").value); 
        UI.addProgress();
      }
    });
    
    i.addEventListener("keyup", function (e) {
      b.disabled = this.value.length < 3; 
      if (e.which === 13) b.click();
    });

    document.getElementById("welcome").classList.remove("hidden");

    i.focus();
  },

  initRoom: function () {
    var opts, path, url = document.getElementById("room-url");

    if (UI.app.config.room === "") {

      UI.app.config.room = UI.app.user.id.substr(-5);
      
      opts = window.location.search ? window.location.search + "&room=" : "?room=";
      path = window.location.pathname + opts + UI.app.config.room;
      
      window.history.replaceState({}, "SecureRoom", path);
    }

    url.value = window.location.href;
    url.classList.remove("hidden");
    url.addEventListener("click", function () { this.select() });
  },

  initInput: function () {
    var m = document.getElementById("message"),
        s = document.getElementById("send");

    m.addEventListener("keyup", function (e) { 
      if (e.which === 13)
        s.click();
    });
    
    s.addEventListener("click", function () { 
      if (m.value !== "") {
        UI.app.sendMessage(m.value);
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
    ctrl.addEventListener("click", function () {
      elem.style.height = "0px";
      while (elem.firstChild) elem.removeChild(elem.firstChild);  
    });
  },

  addMessage: function (message) {
    if (message.verified) {
      var container = document.getElementById("content"),
          build = UI.TemplateEngine("template-message"),
          content = {};

      content.time    = PrintUtil.time(message.sendtime+message.timediff);
      content.sender  = PrintUtil.text((message.sender !== UI.app.user.id) ? UI.app.vault.findUser(message.sender).name : UI.app.user.name);
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
          build     = UI.TemplateEngine("template-key-alert"),
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
      UI.app.channel.sendUser(UI.app.user);
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

  buildRecipientList: function (message) {
    return message.recipients.map(function (id) {
      var recipient = (UI.app.user.ephemeral.id === id) ? UI.app.user : UI.app.vault.findUser(id);
      return (typeof recipient !== "undefined") ? (recipient.status !== "rejected") ? PrintUtil.text(recipient.name) : "REJECTED" : "UNKNOWN";
    }).join(", ");
  },

  buildMsgInfo: function (message) {
    var build = UI.TemplateEngine("template-message-info"),
        content = {info: []};

    content.info.push({term: "Author", data: PrintUtil.id(message.sender)});
    content.info.push({term: "Cipher", data: "AES-CFB 128-bit"});
    content.info.push({term: "Delay", data: message.timediff + " sec"});
    content.info.push({term: "Recipients", data: this.buildRecipientList(message)});

    return build(content);
  },

  buildKeyInfo: function (key) {
    var build = UI.TemplateEngine("template-key-info"),
        content = {};

    content.type = key.isMaster() ? "Master Signing Key" : "Ephemeral Encryption Key";
    content.id   = PrintUtil.id(key.id);
    content.size = PrintUtil.number(key.size);
    content.date = PrintUtil.date(key.created);

    return build(content);
  },

  addToChain: function (user) {
    var chain    = document.getElementById("keychain"),
        build    = UI.TemplateEngine("template-key-chain"),
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
    var container = document.getElementById("welcome"), button;
    
    while (container.firstChild) 
        container.removeChild(container.firstChild);
    
    container.insertAdjacentHTML("beforeend", "<h1>Success!</h1><h3><em>Key <b>" + PrintUtil.id(UI.app.user.id) + "</b> generated.</em></h3><button>Connect &amp; Distribute</button>");
    button = container.querySelector("button");

    button.addEventListener("click", function () {
      UI.app.connectToServer();
      UI.addProgress();
    });

    UI.initRoom();
    UI.initVars();
    UI.addMyUser();

    button.focus();
  },

  addProgress: function () {
    var container = document.getElementById("welcome");
    
    while (container.firstChild) 
        container.removeChild(container.firstChild);

    container.insertAdjacentHTML("beforeend", "<div class='loading'></div>");
  },

  addConnect: function () {
    var action    = "Disconnected",
        container = document.getElementById("welcome");
    
    while (container.firstChild) 
      container.removeChild(container.firstChild);
    
    if (UI.app.channel.isConnected()) {
      action = "Connected";
      UI.app.channel.sendUser(UI.app.user);
      UI.initInput();
    }

    container.parentNode.style.backgroundColor = "white";
    container.style.display = "none";

    document.getElementById("content").insertAdjacentHTML("beforeend", "<li class='event'><div class='time'>" + PrintUtil.time(Math.round(Date.now()/1000)) + "</div><p>" + action + ".</p></li>");
    document.getElementById("message").focus();
  },

  addMyUser: function () {
    var e1 = document.getElementById("my-private-key"),
        e2 = document.getElementById("my-public-key"),
        e3 = document.getElementById("my-key-info"),
        kh = ExportUtil();

    e1.textContent = kh.privateGpg(UI.app.user);
    e2.textContent = kh.publicGpg(UI.app.user);
    e3.insertAdjacentHTML("beforeend", UI.buildKeyInfo(UI.app.user.master) + UI.buildKeyInfo(UI.app.user.ephemeral));

    UI.toggleExport(e1.parentNode, document.getElementById("my-private-key-toggle"));
    UI.toggleExport(e2.parentNode, document.getElementById("my-public-key-toggle"));
    UI.toggleExport(e3, document.getElementById("my-key-info-toggle"));

    document.getElementById("my-name").textContent = PrintUtil.text(UI.app.user.name);
    document.getElementById("my-controls").parentNode.classList.remove("hidden");
  }
}