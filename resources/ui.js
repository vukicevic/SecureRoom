function TemplateEngine(templ) {
  if (typeof templ !== "undefined")
    templ = document.getElementById(templ).innerHTML.replace(/\n|\r/g, "").replace(/>\s+</g, "><").trim();

  return function compile(data, template) {
    var match, tpart, i;

    if (typeof template === "undefined")
      template = templ;

    while (match = /\{\{#([a-zA-Z]+)\}\}(.+)\{\{\/\1\}\}/g.exec(template)) {
      for (tpart = '', i = 0; i < data[match[1]].length; i++)
        tpart += compile(data[match[1]][i], match[2]);

      template = template.split(match[0]).join(tpart);
      delete data[match[1]];
    }

    for (match in data)
      template = template.split('{{' + match + '}}').join(data[match]);

    return template;
  }
}

var UI = {
  toggleKeychain: function() {
    var ctrl = document.getElementById('keychainToggle'),
      elem = document.getElementById('keychain');

    return function (close) {
      if (ctrl.classList.contains('open') || close === 'close') {
        ctrl.classList.remove('open');
        elem.style.bottom = '-' + (elem.clientHeight + 5) + 'px';

        var node;
        while ((node = elem.querySelector('.export:not(.hidden)'))) node.classList.add('hidden');
        while ((node = elem.querySelector('.selected'))) node.classList.remove('selected');
      } else {
        ctrl.classList.add('open');
        elem.style.bottom = (ctrl.clientHeight - 5) + 'px';
      }
    };
  },

  toggleSettings: function() {
    var ctrl = document.getElementById('settingsToggle'),
      elem = document.getElementById('settings');

    return function (close) {
      if (ctrl.classList.contains('open') || close === 'close') {
        ctrl.classList.remove('open');
        elem.style.marginTop = '-' + (elem.clientHeight - ctrl.clientHeight) + 'px';
        window.scrollTo(0, document.body.offsetHeight);
      } else {
        ctrl.classList.add('open');
        elem.style.marginTop = ctrl.clientHeight + 'px';
        window.scrollTo(0, 0);
      }
    };
  },

  toggleKey: function (id, ctrl) {
    return function () {
      if (app.isEnabled(id)) {
        ctrl.classList.add('inactive');
        ctrl.textContent = 'DISABLED';
        app.toggleKey(id, C.STATUS_DISABLED);
      } else {
        ctrl.classList.remove('inactive');
        ctrl.textContent = 'ACTIVE';
        app.toggleKey(id, C.STATUS_ENABLED);
      }
    };
  },

  toggleExport: function (elem, ctrl) {
    return function () {
      if (elem.classList.contains('hidden')) {
        elem.classList.remove('hidden');
        ctrl.classList.add('selected');
      } else {
        elem.classList.add('hidden');
        ctrl.classList.remove('selected');
      }

      elem.style.left = (elem.parentNode.getBoundingClientRect().left - 1) + 'px';
      elem.style.top = '-' + (elem.offsetHeight - (elem.parentNode.getBoundingClientRect().top - elem.parentNode.parentNode.getBoundingClientRect().top)) + 'px';
    };
  },

  toggleSize: function (elem) {
    elem.parentNode.querySelector('.selected').classList.remove('selected');
    elem.classList.add('selected');
    return parseInt(elem.textContent);
  },

  toggleInput: function (close) {
    document.getElementById('input').style.bottom = (close) ? '-2.3125em' : '0em';
  },

  toggleRoom: function () {
    document.getElementById('room').textContent = 'Room: ' + app.getRoom();
  },

  toggleHeight: function (elem) {
    var height = elem.offsetHeight;

    if (elem.classList.contains('hidden-height')) {
      elem.style.height = '0px';
      elem.classList.remove('hidden-height');
    } else {
      elem.style.height = height + 'px';
    }

    return function () {
      elem.style.height = (elem.style.height == '0px') ? height + 'px' : '0px';
    }
  },

  removeContent: function (elem) {
    elem.style.height = elem.offsetHeight + 'px';

    return function () {
      elem.style.height = '0px';
      while (elem.firstChild) elem.removeChild(elem.firstChild);
    }
  },

  disableSettings: function (setting) {
    var parent = document.getElementById(setting), node;

    switch (setting) {
      case 'asymsize':
        while ((node = parent.querySelector('span:not(.selected)'))) parent.removeChild(node);
        break;
      case 'serverurl':
        parent.classList.add('selected');
        parent.contentEditable = false;
        break;
    }
  },

  addMessage: function (message) {
    if (message.isVerified()) {
      var container = document.getElementById("content"),
        build = TemplateEngine("template-message"),
        content = {};

      content.time = PrintUtil.time(message.getTime());
      content.sender = PrintUtil.text(app.getKey(message.getSender()).name);
      content.message = PrintUtil.text(message.getText());
      content.info = UI.buildMsgInfo(message);
      content.class = (message.isVerified()) ? "" : " warning";

      container.insertAdjacentHTML("beforeend", build(content));

      UI.addMessageListeners(container.lastChild);
      window.scrollTo(0, document.body.offsetHeight);
    }
  },

  addMessageListeners: function (elem) {
    elem.addEventListener('click', UI.toggleHeight(elem.querySelector('.info')));
  },

  addKey: function (id) {
    if (!document.getElementById('alert-' + id)) {
      var container = document.getElementById('content'),
          build     = TemplateEngine('template-key-alert'),
          content   = {};

      content.id   = PrintUtil.text(id);
      content.time = PrintUtil.time(Math.round(Date.now() / 1000));
      content.name = PrintUtil.text(app.getKey(id).name);
      content.info = UI.buildKeyInfo(id);

      container.insertAdjacentHTML('beforeend', build(content));

      UI.addKeyListeners(document.getElementById('alert-' + id), id);
      window.scrollTo(0, document.body.offsetHeight);
    }
  },

  addKeyListeners: function (elem, id) {
    var a = elem.getElementsByTagName('button').item(0),
      r = elem.getElementsByTagName('button').item(1),
      p = elem.querySelector('.join'),
      d = UI.removeContent(a.parentNode);

    a.addEventListener('click', function () {
      app.toggleKey(id, C.STATUS_ENABLED);
      com.sendKey();
    });

    a.addEventListener('click', function () {
      p.classList.add('accept');
      UI.buildKeychain();
    });

    a.addEventListener('click', d);

    r.addEventListener('click', function () {
      app.toggleKey(id, C.STATUS_REJECTED);
    });

    r.addEventListener('click', function () {
      elem.classList.add('warning');
      p.classList.add('reject');
    });

    r.addEventListener('click', d);
  },

  buildRecipientList: function(message) {
    return message.getRecipients().map(function(id) {
      return (app.hasKey(id)) ? (!app.isRejected(id)) ? PrintUtil.text(app.getKey(id).name) : 'Rejected' : 'Unknown';
    }).join(', ');
  },

  buildMsgInfo: function (message) {
    var build = TemplateEngine('template-message-info'),
      content = {info: []};

    content.info.push({term: 'Author', data: PrintUtil.id(message.getSender())});
    //content.info.push({term: 'Cipher', data: Symmetric.name+'-'+(message.sessionkey.length*8)+' ['+Symmetric.mode+']'});
    content.info.push({term: 'Delay', data: message.getTimeDiff() + ' sec'});
    content.info.push({term: 'Recipients', data: this.buildRecipientList(message)});

    return build(content);
  },

  buildKeyInfo: function (id) {
    var build = TemplateEngine('template-key-info'),
      content = {};

    content.sid = PrintUtil.id(id);
    content.ssize = PrintUtil.number(app.getKey(id).size);
    content.sdate = PrintUtil.date(app.getKey(id).time);

    return build(content);
  },

  buildKeychain: function () {
    var container = document.getElementById('keychain'),
      build = TemplateEngine('template-key-chain'),
      content = {};

    while (container.lastChild != container.firstChild)
      container.removeChild(container.lastChild);

    for (var i = 0, d = app.getKeys(C.TYPE_MASTER, C.STATUS_ENABLED | C.STATUS_DISABLED); i < d.length; i++) {
      content.id = PrintUtil.text(d[i]);
      content.name = PrintUtil.text(app.getKey(d[i]).name);
      content.status = (app.isEnabled(d[i])) ? '' : 'inactive';
      content.state = (app.isEnabled(d[i])) ? 'ACTIVE' : 'DISABLED';
      content.info = UI.buildKeyInfo(d[i]);
      content.data = KeyHelper(app.getKey(d[i]), app.getKey(app.getKey(d[i]).peer)).getPublicGpgKey();

      container.insertAdjacentHTML('beforeend', build(content));
      UI.addKeychainListeners(container.lastChild, d[i]);
    }

    UI.toggleKeychain()('close');
  },

  addKeychainListeners: function (elem, id) {
    var b1 = elem.getElementsByTagName('span').item(0),
      b2 = elem.getElementsByTagName('span').item(1),
      ex = elem.querySelector('.export');

    b1.addEventListener('click', UI.toggleKey(id, b1));
    b2.addEventListener('click', UI.toggleExport(ex, b2));
  },

  addWelcome: function (type) {
    var container = document.getElementById('welcome');
    while (container.firstChild)
      container.removeChild(container.firstChild);

    switch (type) {
      case 'distribute':
        container.insertAdjacentHTML('beforeend', '<p>Your keys have been generated.</p><div class="info">' + UI.buildKeyInfo(app.myId(C.TYPE_MASTER)) + '</div><button>Connect &amp; Distribute</button>');
        container.querySelector('button').addEventListener('click', function () {
          com.connect();
          UI.addWelcome('progress');
          UI.disableSettings('serverurl')
        });
        UI.addMyKey();
        break;
      case 'progress':
        container.insertAdjacentHTML('beforeend', '<div class="loading"></div>');
        break;
      case 'connect':
        container.insertAdjacentHTML('beforeend', '<div class="time">' + PrintUtil.time(Math.round(Date.now() / 1000)) + '</div><p>Connected.</p>');
        break;
      case 'disconnect':
        container.insertAdjacentHTML('beforeend', '<div class="time">' + PrintUtil.time(Math.round(Date.now() / 1000)) + '</div><p>Disconnected.</p>');
        break;
    }
  },

  addMyKey: function () {
    document.getElementById('myname').textContent = PrintUtil.text(app.myName());
    document.getElementById('myinfo').insertAdjacentHTML('beforeend', UI.buildKeyInfo(app.myId(C.TYPE_MASTER)));

    var my = document.getElementById('mykey'),
      e1 = my.getElementsByTagName('textarea').item(0),
      e2 = my.getElementsByTagName('textarea').item(1),
      b1 = my.getElementsByTagName('span').item(0),
      b2 = my.getElementsByTagName('span').item(1),
      kh = KeyHelper(app.getKey(app.myId(C.TYPE_MASTER)), app.getKey(app.myId(C.TYPE_EPHEMERAL)));

    e1.textContent = kh.getSecretGpgKey();
    e2.textContent = kh.getPublicGpgKey();

    b1.addEventListener('click', UI.toggleExport(e1.parentNode, b1));
    b2.addEventListener('click', UI.toggleExport(e2.parentNode, b2));
  }
}