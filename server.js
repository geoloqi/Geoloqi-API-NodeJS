var http = require('http');
var fs = require('fs');
var config_file = fs.readFileSync('ritalin.config','ascii');
var config = JSON.parse(config_file);
var crypto = require('crypto');
var sys = require('sys');
var spawn = require('child_process').spawn;
var url = require('url');
var Buffer = require('buffer').Buffer;
var redis = require('redis-client').createClient();
var expires = new Date();
expires.setDate(expires.getDate() - 100000);
expires = expires.toUTCString();
var when = new Date();
when.setDate(when.getDate() + 14);
when.toUTCString();
var b64 = require('base64');
var Session = new Object;
if (config.bot == 1) 
{ 
	var irc = require('irc');
	var client = new irc.Client(config.bot_server,config.bot_name,
	{
		channels: [config.bot_channel],
	});
	client.on("error", function(error)
	{
		console.log(lookUp(error));
		console.log(error.stack);
	});


	
}
var dgram = require('dgram');
var udp = dgram.createSocket('udp4');

function hitAPI(host,path,data,port,method){
	var web_client = http.createClient(port,"http://" + host);
	var request = web_client.request(method,path, {'host': host});
	request.write(data);
	request.end();
	console.log(sys.inspect(request));
	request.on('response', function(response){
		response.on('data', function(data){
			console.log(data);
		});
	});
}

function sendLocation(){
	var d = new Date();
	//console.log(ISODateString(d));
	var date = ISODateString(d);
	var packet = fs.readFileSync("packet","ascii");
	hitAPI("tyler-postbin.appspot.com","/1grwu0e",packet,80,"POST");
}

				
udp.on('error', function(message)
{
	console.log(message);
});
udp.bind(config.udp_port);
udp.on('message', function(message,rinfo)
{
	message = JSON.parse(message);
	var signature = message.signature;
	var text = message.text;
	var name = message.name;
	var publicKey;
	var web_client = http.createClient(config.port,config.domain)
	var getKey = web_client.request("/keys/" + name,{'host': 'rital.in'})
	getKey.end();
	getKey.on('response', function(response)
	{
		response.on('data', function(data)
		{
			console.log(data);
			publicKey = data;
			var verified = crypto.createVerify('RSA-SHA256').update(text).verify(publicKey,signature,'hex');
			if (verified && client)
			{
				client.say(config.bot_channel, name + " " + "sent '" + text + "' [ http://" + config.domain + ":" + config.port + "/keys/" + name + " ]");
			} 

		});
	});	
	
	
});

function newKey(user)
{
	var key = spawn('openssl', ['req', '-nodes', '-newkey', 'rsa:1024', '-x509', '-keyout', 'keys/' + user + '.pem', '-out', 'keys/' + user + '-pub.pem', '-days', '1095', '-batch']);
	key.stdout.on('data', function(data){
		console.log(data);
	});
	key.stderr.on('data', function(data){
		console.log(data);
	});
}

function ISODateString(d){
 
 function pad(n){return n<10 ? '0'+n : n}
 return d.getUTCFullYear()+'-'
      + pad(d.getUTCMonth()+1)+'-'
      + pad(d.getUTCDate())+'T'
      + pad(d.getUTCHours())+':'
      + pad(d.getUTCMinutes())+':'
      + pad(d.getUTCSeconds())+'Z'
}

Date.prototype.setISO8601 = function(dString){
	var regexp = /(\d\d\d\d)(-)?(\d\d)(-)?(\d\d)(T)?(\d\d)(:)?(\d\d)(:)?(\d\d)(\.\d+)?(Z|([+-])(\d\d)(:)?(\d\d))/;
	if (dString.toString().match(new RegExp(regexp))) {
		var d = dString.match(new RegExp(regexp));
		var offset = 0;
		this.setUTCDate(1);
		this.setUTCFullYear(parseInt(d[1],10));
		this.setUTCMonth(parseInt(d[3],10) - 1);
		this.setUTCDate(parseInt(d[5],10));
		this.setUTCHours(parseInt(d[7],10));
		this.setUTCMinutes(parseInt(d[9],10));
		this.setUTCSeconds(parseInt(d[11],10));
		if (d[12])
			this.setUTCMilliseconds(parseFloat(d[12]) * 1000);
		else
			this.setUTCMilliseconds(0);
		if (d[13] != 'Z') {
			offset = (d[15] * 60) + parseInt(d[17],10);
			offset *= ((d[14] == '-') ? -1 : 1);
			this.setTime(this.getTime() - offset * 60 * 1000);
		}
	}
	else {
		this.setTime(Date.parse(dString));
	}
	return this;
};

function randomString() {
	var chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz";
	var string_length = 32;
	var randomstring = '';
	for (var i=0; i<string_length; i++) {
		var rnum = Math.floor(Math.random() * chars.length);
		randomstring += chars.substring(rnum,rnum+1);
	}
	return randomstring;
}
console.log(randomString());

http.createServer(function (req, res) {
	function writeOut(obj){
		status = obj.status || 200;
		headers = obj.headers || new Object;
		if (!headers['content-type']){
			headers['content-type'] = "text/html";
		}
		data = obj.data;
		console.log(sys.inspect(headers));
		res.writeHead(status, headers);
		res.end(data + "\n");
	}
	try {
		var path = req.url.substr(1);
		var key = /^\/key\/(.*)/.exec(req.url);
		var login = /.*\/login.*/.exec(req.url);
		key = key || 0;
		var incoming = /^\/incoming.*/.exec(req.url);
		incoming = incoming || 0;
		login = login || 0;
		var params = url.parse(req.url,true).query;
		params = params || 0;
		var resource = url.parse(req.url,true).pathname;
		var name = req.headers.cookie
		name = /name=(\w+)/.exec(req.headers.cookie)
		if (name){ name = name[1] };
		appname = /^\/apps\/(.*)/.exec(req.url);
		appname = appname || 0;
		auth = /^\/oauth\/authorize/;
	
		switch(resource)
		{
			
				case "/": 
				{
					console.log(sys.inspect(req));
					if (req.headers.cookie){
						res.writeHead(302, {'Location': '/main' });
						res.end('set cookie');
					}
					else {
						
						res.writeHead(200, {'Content-Type': 'text/html'});
						index = fs.readFileSync("public/index.html");
						if (params && params.error){
							index = index.toString().replace(/ERROR/,
								"<div style='color:red;border-stlye:solid;border-color:red;border-width:3px;'>Username or Password incorrect<br><br></div>");
						}else {
							index = index.toString().replace(/ERROR/,"");
						}
						res.end(index);
						
					}
					break;
				}
				case "/login":{
					name = params.user;
					pass = params.pass;
					redis.get("ritalin:" + name + ":password", function(err,password){
						
						if (password && password.toString() == pass) {
							console.log("login good");
							res.writeHead(302, {'Location':'/main', 'set-cookie':'name=' + name + '; expires=' + when } );
							res.end('');
						}
						else {
							writeOut({status:302,headers:{"Location":"/?error=1"}});
						}
					});
					break;
				}
				case "/main":{
					
					if (!req.headers.cookie){ 
						res.writeHead(302, {'Location': '/' });
						res.end('');
					} else {
						
						main = fs.readFileSync('public/main.html');
						
						//newKey(name);
						main = main.toString().replace(/NAME/g,name);
						res.writeHead(200, {'Content-Type': 'text/html' });
						res.end(main);
					}
					break;
				}
				case "/logout":{
					res.writeHead(302, {'Content-Type': 'text/plain', 'set-cookie':'name=tyler;expires=' + expires, 'Location': '/'});
					res.end('');
				}
				case "/oauth/authorize": 
					
					if (!params) { 
						writeOut({status:401,data:"no params in request!"});
						break;
					}
					
					console.log("requesting auth");
					redirect = params['redirect_uri'];
					scope = params.scope;
					client_id = params['client_id'];
					code = randomString();
					if (req.headers.cookie){
						writeOut({data:"Hello " + name + ". Grant access to " + client_id + "? <a href='" + redirect + "?code=" + code + "'>YES</a>"});
					} else {
						//writeOut({ status:302, headers: { 'Location':redirect + '?scope=' + scope + '&code=' + code} });
						writeOut({data:"TODO"}); //TODO
					}
					break;
				case "/oauth/token": case "/oauth/access_token":
					//console.log(req.url);
					var postData = "";
					var code;
					req.addListener("data", function (chunk) { postData += chunk }) 
					req.addListener("end", function () { 
						// now postData is full. 
						var message = "You posted: "+postData 
						//console.log(postData);
						code = /code=(.*)/.exec(postData);
						if (code) { code = code[1]; }
						//console.log(code);
					});
					//console.log(sys.inspect(req));
					/*
					if (!params) { 
						writeOut({status:401,data:"no params in request!"});
						break;
					}
					*/
					access_token = randomString();
					refresh_token = randomString();
					if (params['grant_type'] == "password"){
						//console.log(sys.inspect(req));
						auth_pieces = req.headers['authorization'].split(" ");
						if (auth_pieces[0] == "Basic"){
							id_secret = b64.decode(new Buffer(auth_pieces[1])).split(":");
							redis.get("ritalin:apptoken:" + id_secret[0], function(err,appsecret){
								try {
									if (appsecret.toString() == id_secret[1]){
							
										redis.get("ritalin:" + params.username + ":password", function(err, password){
											console.log(sys.inspect(params.password) + " " + sys.inspect(password.toString('ascii')));
											if (params.password == password.toString('ascii')){
												redis.set("ritalin:" + params.username + ":access_token",access_token);
												redis.set("ritalin:access_token:" + access_token, params.username);
												output = { access_token:access_token,expires_in:3600 };
												output = JSON.stringify(output);

												writeOut({data:output,headers:{"content-type":"application/json"}});
											}
										});
									}
								} catch (e) {
									writeOut({data:"That clientid does not exist!\n"});
								}
							});
						} else {
							writeOut({data:"Sorry thats not the right auth method",status:401});
						}
					}else {
						output = { access_token:access_token,refresh_token:refresh_token };
						output = JSON.stringify(output);
						writeOut({data:output});
					}
					break;
				case "/account/username":
					if (!params.oauth_token) { writeOut({status:401,data:"NO!"}); break; }
					redis.get("ritalin:access_token:" + params.oauth_token, function(err, username){
						console.log("access_name is: " + username.toString());
						output = JSON.stringify({username:username.toString()});
						writeOut({data:output});
						
					});
					break;
				case "/location/last":
					console.log(params.oauth_token);
					redis.get("ritalin:access_token:" + params.oauth_token, function(err, username){
						if (!username){ writeOut({status:401,data:"Something went wrong. Probably no oauth_token"}); return; }
						console.log("foo");
						redis.get("ritalin:" + username.toString() + ":last_location", function(err, last_location){
							
							writeOut({data:last_location.toString()});
						});
					});
					
					break;
				case "/location/update":
					var postData = "";
					var code;
					var foo;
					req.addListener("data", function (chunk) { postData += chunk }) 
					
					req.addListener("end", function () { 
						// now postData is full. 
						var message = "You posted: "+postData 
						console.log(postData);
						code = /code=(.*)/.exec(postData);
						if (code) { code = code[1]; }
						try { var locations = JSON.parse(postData); 
							//console.log(code);
							token = params.oauth_token || "G1QK8TEM9qZK8g8URMDz9fxdUZr4173x";
							redis.get("ritalin:access_token:" + token, function(err, username){
								redis.set("ritalin:" + username.toString() + ":last_location", JSON.stringify(locations[0]));
								redis.get("ritalin:" + username.toString() + ":location_history", function(err,history){
									history = history || "[]";
									console.log("history: " + history);
									history = JSON.parse(history.toString());
									for(i=0;i<locations.length;i++){
										history.push(locations[i]);
									}
									history = JSON.stringify(history);
									redis.set("ritalin:" + username.toString() + ":location_history", history);
								});
								
							});
						}
						catch(e) {
							writeOut({data:"You broke it!",status:401});
						}

					});
					writeOut({data:"thanks"});
					break;
				case "/location/history":
					function rad(num){
						return num * (Math.PI/180);
					}

					var newDate = new Date();
					var now = new Date();
					
					params.count = params.count || 100;
					params.accuracy = params.accuracy || 100;
					redis.get("ritalin:access_token:" + params.oauth_token, function(err, username){
						redis.get("ritalin:" + username.toString() + ":location_history", function(err, location_history){
							
							history = JSON.parse(location_history.toString());
							foo = [];
							location_history = [];
							for(i=0;i<history.length;i++){
								db_lat = history[i].location.position.latitude;
								db_lon = history[i].location.position.longitude;
								if (params.geometry){
									if (params.geometry == "circle"){
										if (params.center && params.radius){
											
											lat_lon = params.center.split(",");
											param_lat = lat_lon[0];
											param_lon = lat_lon[1];
											d = 3959 * Math.acos(Math.cos(rad(param_lat)) 
												* Math.cos(rad(db_lat)) * Math.cos(rad(db_lon) - 
												rad(param_lon)) + Math.sin(rad(param_lat)) * Math.sin(rad(db_lat)));
											if (d > params.radius){ continue; }
										}
										else{ writeOut({status:401,data:"Missing center!"}); }
									}
									if (params.geometry == "rectangle"){
										if(params.sw && params.ne){
											sw_lat_lon = params.sw.split(",");
											ne_lat_lon = params.ne.split(",");
											sw_lat = sw_lat_lon[0];
											sw_lon = sw_lat_lon[1];
											ne_lat = ne_lat_lon[0];
											ne_lon = ne_lat_lon[1];
											if (db_lat < sw_lat || db_lat > ne_lat || db_lon < sw_lon || db_lon > ne_lon){ continue; }
										}
									}
										
								}
								if (history[i].location.position.horizontal_accuracy > params.accuracy) { continue; console.log("too big"); }
								//console.log(history[i].location.position.horizontal_accuracy);
								//console.log(params.accuracy);
								//console.log(history[i].date);
								dateString = /(.*)-(\d\d\d)/.exec(history[i].date);
								newDate.setISO8601(dateString[1]+"-0"+dateString[2]);
								
								if (params.after){
									var since = new Date();
									since.setTime(params.after * 1000);
									if (since == "Invalid Date"){ since.setISO8601(params.after); console.log(since); }
									//since = since.toUTCString();
									if (since <= newDate) { 
										console.log(JSON.stringify(history[i]));
										foo.push(history[i]);
									}
								}
								
								location_history.push(history[1]);
								if (i == params.count - 1){ break; }
							}
							if (foo.length > 0 ){ writeOut({data:JSON.stringify(foo)}); }
							else { writeOut({data:JSON.stringify(location_history)}); }
						});
					});
					break;


				case "/json":
					test = JSON.stringify({"test":"json"});
					writeOut({data:test});
					break;
				case appname[0]:
					redis.get("ritalin:apptoken:" + appname[1], function(error, token){
						console.log(token);
						output = "App Id:<br> <b>" + appname[1] + "</b><br><br>" +
								"App Secret:<br> <b>" + token + "</b><br><br><a href='/apps'>Back to apps</a>";
						writeOut({data:output});
					});
					break;
				case "/apps":
					if (req.headers.cookie){
						
						redis.smembers("ritalin:apps:" + name,function(error,value){
							
							for (i=0; i < value.length; i++){
								value[i] = "<a href='/apps/" + value[i] + "'>" + value[i] + "</a>"
							}
							output = fs.readFileSync("public/apps.html","ascii");
							output = output.replace(/APPS/g,value);
							writeOut({data:output});
						});
					} else {
						writeOut({headers: {'Location':'/'}, status:302});
					}
					break;
				case key[0]:
				{
					path = config.install_path + '/keys/' + key[1] + '-pub.pem'
					publicKey = fs.readFileSync(path,'ascii');
					console.log(path);
					res.writeHead(200, {'Content-Type': 'text/plain'});
					res.end(publicKey);
					break;
				}
				case incoming[0]:
				{
					packet = JSON.parse(params.body);
					
					domain = packet.domain;
					name = packet.name;
					text = packet.text;
					signature = packet.signature;
					var web_client = http.createClient(80,domain)
					var getKey = web_client.request("/key/" + name,{'host': domain})
					var verified;
					getKey.end();
					getKey.on('response', function(response)
					{
						response.on('data', function(data)
						{
							console.log(data);
							publicKey = data;
							verified = crypto.createVerify('RSA-SHA256').update(text).verify(publicKey,signature,'hex');
							console.log(verified);
							if (verified == 1){
								res.writeHead(200, {'Content-Type': 'text/plain'});
								res.end("You sent: " + params.body + "\n\nMessage verified");
							}
							else {
								res.writeHead(401, {'Content-Type': 'text/plain'});
								res.end("Verification failed");
							}


						});
					});
					break;
					
				}
				default: 
					res.writeHead(404, {'Content-Type': 'text/plain'}); res.end("File doesn't exist");
					//console.log(sys.inspect(req));
					var postData = "";
					var code;
					req.addListener("data", function (chunk) { postData += chunk }) 
					req.addListener("end", function () { 
						// now postData is full. 
						var message = "You posted: "+postData 
						console.log(postData);
						code = /code=(.*)/.exec(postData);
						if (code) { code = code[1]; }
						//console.log(code);
					});
					break;
		}			
	} catch(e)
	{
		res.writeHead(500, {'Content-Type': 'text/plain'}); res.end("There has been an error: " + e.message);
	}

}).listen(config.port, "0.0.0.0");
console.log('Server running at http://' + config.domain + ':' + config.port + '/');