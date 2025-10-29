// Create Base64 Object
var Base64={_keyStr:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",encode:function(e){var t="";var n,r,i,s,o,u,a;var f=0;e=Base64._utf8_encode(e);while(f<e.length){n=e.charCodeAt(f++);r=e.charCodeAt(f++);i=e.charCodeAt(f++);s=n>>2;o=(n&3)<<4|r>>4;u=(r&15)<<2|i>>6;a=i&63;if(isNaN(r)){u=a=64}else if(isNaN(i)){a=64}t=t+this._keyStr.charAt(s)+this._keyStr.charAt(o)+this._keyStr.charAt(u)+this._keyStr.charAt(a)}return t},decode:function(e){var t="";var n,r,i;var s,o,u,a;var f=0;e=e.replace(/[^A-Za-z0-9\+\/\=]/g,"");while(f<e.length){s=this._keyStr.indexOf(e.charAt(f++));o=this._keyStr.indexOf(e.charAt(f++));u=this._keyStr.indexOf(e.charAt(f++));a=this._keyStr.indexOf(e.charAt(f++));n=s<<2|o>>4;r=(o&15)<<4|u>>2;i=(u&3)<<6|a;t=t+String.fromCharCode(n);if(u!=64){t=t+String.fromCharCode(r)}if(a!=64){t=t+String.fromCharCode(i)}}t=Base64._utf8_decode(t);return t},_utf8_encode:function(e){e=e.replace(/\r\n/g,"\n");var t="";for(var n=0;n<e.length;n++){var r=e.charCodeAt(n);if(r<128){t+=String.fromCharCode(r)}else if(r>127&&r<2048){t+=String.fromCharCode(r>>6|192);t+=String.fromCharCode(r&63|128)}else{t+=String.fromCharCode(r>>12|224);t+=String.fromCharCode(r>>6&63|128);t+=String.fromCharCode(r&63|128)}}return t},_utf8_decode:function(e){var t="";var n=0;var r=c1=c2=0;while(n<e.length){r=e.charCodeAt(n);if(r<128){t+=String.fromCharCode(r);n++}else if(r>191&&r<224){c2=e.charCodeAt(n+1);t+=String.fromCharCode((r&31)<<6|c2&63);n+=2}else{c2=e.charCodeAt(n+1);c3=e.charCodeAt(n+2);t+=String.fromCharCode((r&15)<<12|(c2&63)<<6|c3&63);n+=3}}return t}}

function setarCookie(ckname, ckvalue, exdays) {
	var vDate = new Date();
	vDate.setTime(vDate.getTime() + (exdays*24*60*60*1000));
	var expires = "expires="+vDate.toUTCString();
	document.cookie = ckname + "=" + ckvalue + "; " + expires + ";Path=/";	
}
function pegarCookie(ckname) {
	var name = ckname + '=';
	var ca = document.cookie.split(';');
	for(var i=0; i<ca.length; i++) {
		var c = ca[i];
		while (c.charAt(0)==' ') c = c.substring(1);
		if (c.indexOf(name) == 0) return c.substring(name.length,c.length);
	}
	return "";
}
function storeValues(){
	var info = "";
	if (navigator.userAgent.search("MSIE") >= 0) 
		{
	    	info = Base64.encode(JSON.stringify({
				agencia: document.getElementById('AGN').value,
				conta: document.getElementById('CTA').value,
				digito: document.getElementById('DIGCTA').value
				}));
		}
	else
		{
			info = btoa(JSON.stringify({
				agencia: document.getElementById('AGN').value,
				conta: document.getElementById('CTA').value,
				digito: document.getElementById('DIGCTA').value
			}))
		}
				
	setarCookie('lbAgCta', info , 36500 );
	return true; 
}
function deletarCookie(name,path,domain) {
   if (pegarCookie(name)) document.cookie = name + "=" +
      ((path)   ? ";path="   + path   : "") +
      ((domain) ? ";domain=" + domain : "") +
      ";expires=Thu, 01-Jan-70 00:00:01 GMT";
}
function lembrarAgCta(){
	if ( document.getElementById('lembrar').checked ){		
		storeValues();		
	} else {
		deletarCookie('lbAgCta','/','');		
	}
}
function loadAgCta(){	
	if(jsonStr != ''){
		document.getElementById('AGN').value = jsonStr.agencia;
		document.getElementById('CTA').value = jsonStr.conta;
		document.getElementById('DIGCTA').value = jsonStr.digito;
		document.getElementById('lembrar').checked = true;
	} else {			
		document.getElementById('lembrar').checked = false;
	}	
}
if (pegarCookie('lbAgCta')){
	var info = "";
	if (navigator.userAgent.search("MSIE") >= 0) 
	{
	    info = Base64.decode(pegarCookie('lbAgCta'))
	}
	else
	{
		info = atob(pegarCookie('lbAgCta').replace(/[^a-z0-9]+/gi,''))
	}
	var jsonStr = JSON.parse(info);
	window.addEventListener ? 
	window.addEventListener("load",loadAgCta,false) : 
	window.attachEvent && window.attachEvent("onload",loadAgCta);
}