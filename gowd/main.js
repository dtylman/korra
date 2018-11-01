var os = require('os');
var child;
var fails = 0;
var goBinary = "./korra"; 

function setPage(html) {
    const container = document.getElementById("app");
    app.innerHTML = html;
    //set focus for autofocus element
    var elem = document.querySelector("input[autofocus]");
    if (elem != null) {
        elem.focus();
    }    
}

function body_message(msg) {
    setPage('<div class="header pb-8 pt-5 pt-lg-8 d-flex align-items-center" style="min-height: 600px; background-image: url(./assets/img/brand/korra.png); background-size: cover; background-position: center;">'+
    '<span class="mask bg-gradient-default opacity-8"></span><div class="container-fluid d-flex align-items-center"></div><div class="col-lg-7 col-md-10">'
    +'<h1 class="display-2 text-white">'+msg+'</h1></div></div>');
}

function start_process() {
    if (os.platform().isWindows) {
        goBinary += ".exe";
    }
    
    body_message("Loading...");    

    const spawn = require('child_process').spawn;
    child = spawn(goBinary, { maxBuffer: 1024 * 500 });

    const readline = require('readline');
    const rl = readline.createInterface({
        input: child.stdout
    })

    rl.on('line', (data) => {
        console.log(`Received: ${data}`);

        if (data.charAt(0) == "$") {
            data = data.substr(1);
            eval(data);
        } else {
            setPage(data);
        }
    });

    child.stderr.on('data', (data) => {
        console.log(`stderr: ${data}`);
    });

    child.on('close', (code) => {
        body_message(`process exited with code ${code}`);
        restart_process();
    });

    child.on('error', (err) => {
        body_message('Failed to start child process.');
        restart_process();
    });
}

function restart_process() {
    setTimeout(function () {
        fails++;
        if (fails > 5) {
            close();
        } else {
            start_process();
        }
    }, 5000);
}

function element_as_object(elem) {
    var obj = {
        properties: {}
    }
    for (var j = 0; j < elem.attributes.length; j++) {
        obj.properties[elem.attributes[j].name] = elem.attributes[j].value;
    }
    //overwrite attributes with properties
    if (elem.value != null) {
        obj.properties["value"] = elem.value.toString();
    }
    if (elem.checked != null && elem.checked) {
        obj.properties["checked"] = "true";
    } else {
        delete (obj.properties["checked"]);
    }
    return obj;
}

function element_by_tag_as_array(tag) {
    var items = [];
    var elems = document.getElementsByTagName(tag);
    for (var i = 0; i < elems.length; i++) {
        items.push(element_as_object(elems[i]));
    }
    return items;
}

function fire_event(name, sender) {
    var msg = {
        name: name,
        sender: element_as_object(sender),
        inputs: element_by_tag_as_array("input").concat(element_by_tag_as_array("select"))
    }
    child.stdin.write(JSON.stringify(msg));
    console.log(JSON.stringify(msg));
}

function fire_keypressed_event(e, keycode, name, sender) {
    if (e.keyCode === keycode) {
        e.preventDefault();
        fire_event(name, sender);
    }
}

function avoid_reload() {
    if (sessionStorage.getItem("loaded") == "true") {
        alert("go-webkit will fail when page reload. avoid using <form> or submit.");
        close();
    }
    sessionStorage.setItem("loaded", "true");
}


function maximize_window(){
    var ngui = require('nw.gui');
    var nwin = ngui.Window.get();
    nwin.show();
    nwin.maximize();
}

avoid_reload();
start_process();
maximize_window();