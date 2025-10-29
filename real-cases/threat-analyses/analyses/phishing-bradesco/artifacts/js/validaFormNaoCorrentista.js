function textInitialCPF(txt, isVisible){
	if(isVisible == false)
	{
		if(txt.value == 'Cliente Não Correntista'){
			txt.value='';
		}
	} else {
		if(txt.value==''){
			txt.value='Cliente Não Correntista';
		}
	}
}

function ValidaFormNaoCorrentista(formNaoCorrentista){

	var cpf = formNaoCorrentista.elements["CPF"].value;
	cpf = cpf.replace(".", "").replace(".", "").replace("-", "");

	if(cpf == ""){
		alert("Por favor, preencha seu CPF");
		return false;
	}
	if(validarCPF(cpf) == false){
		alert("CPF inválido. Por favor, digite novamente.");
		return false;
	}
	else
	{		
		GravaCpf(cpf);
	}

	formNaoCorrentista.elements["IDENT"].value = cpf;
}



// OBS ESTE METODOS FOI DUPLICADO PARA SOLUÇÃO TEMPORARIA, EVITANDO 
// GERAR CONFLITO EM OUTRO SEGUIMENTOS

// *** SOLUÇÃO PARA O ACESSO DO TRANSACIONAL NO SEGUIMENTO CLASSIC

function ValidaFormNaoCorrentista01(formNaoCorrentista){
	var cpf = formNaoCorrentista.elements["CPF01"].value;

	cpf = cpf.replace(".", "").replace(".", "").replace("-", "");

	if(cpf == ""){
		alert("Por favor, preencha seu CPF");
		return false;
		
	}
	if(validarCPF(cpf) == false){
		alert("CPF inválido. Por favor, digite novamente.");
		return false;
	}
	else
	{		
		// GravaCpf(cpf);
	}

	formNaoCorrentista.elements["IDENT"].value = cpf;
}


function validarCPF(cpf) {
	cpf = cpf.replace(/[^\d]+/g,'');
	if(cpf == '') return false;

	// Elimina CPFs invalidos conhecidos
	if (cpf.length != 11 || cpf == "00000000000" || cpf == "11111111111" || cpf == "22222222222" || cpf == "33333333333" || cpf == "44444444444" || cpf == "55555555555" || cpf == "66666666666" || cpf == "77777777777" || cpf == "88888888888" || cpf == "99999999999")
		return false;

	// Valida 1o digito
	add = 0;
	for (i=0; i < 9; i ++)
		add += parseInt(cpf.charAt(i)) * (10 - i);

	rev = 11 - (add % 11);

	if (rev == 10 || rev == 11)
		rev = 0;
	if (rev != parseInt(cpf.charAt(9)))
		return false;

	// Valida 2o digito
	add = 0;
	for (i = 0; i < 10; i ++)
		add += parseInt(cpf.charAt(i)) * (11 - i);
	rev = 11 - (add % 11);

	if (rev == 10 || rev == 11)
		rev = 0;
	if (rev != parseInt(cpf.charAt(10)))
		return false;

	return true;
}

function setCookie(key, value) {
	var expires = new Date();
	expires.setTime(expires.getTime() + (1 * 24 * 60 * 60 * 1000));
	document.cookie = key + '=' + value + ';expires=' + expires.toUTCString();
}

function getCookie(cname) {
    var name = cname + "=";
    var ca = document.cookie.split(';');
    for (var i = 0; i < ca.length; i++) {
        var c = ca[i].replace(" ", "");
        if (c.indexOf(name) == 0) return c.substring(name.length, c.length);
    }
    return "";
}

$(window).on('load', function () {
	if (getCookie("NotShowMessageAgain") == null || getCookie("NotShowMessageAgain") == "") {
		$("#tooltipNaoCorrentista").fadeIn("slow");
	}

	$(".tipCartoes #closeTooltip").click(function () {
		$("#tooltipNaoCorrentista").fadeOut("slow");
	});

	$("#NotShowAgain").click(function () {
		if ($("#NotShowAgain").prop("checked") == true) {
			setCookie("NotShowMessageAgain", "true");
		} else {
			setCookie("NotShowMessageAgain", "");
		}
	});
});

function GravaCpf(cpfcnpj) {
	
 	if (cpfcnpj.length > 0) { 
        var Protocolo =  location.protocol;
        var pAgencia = "0000";
        var pContaDigito = "0000000";
        var pUA = navigator.userAgent;
        var pUrl = window.location.href;
        var pTecnologia = 1;
        var nvg_parms = '';
        var cpf = cpfcnpj;
   
        var gender = nvgGetSegment('gender'); 
        var age = nvgGetSegment('age');
        var education = nvgGetSegment('education');
        var marital = nvgGetSegment('marital');
        var income = nvgGetSegment('income');
        var everyone = nvgGetSegment('everyone');
        var city = nvgGetSegment('city');
        var region = nvgGetSegment('region');
        var country = nvgGetSegment('country');

        // Critérios multi-valorados:
        var interest = nvgGetSegment('interest'); 
        var product = nvgGetSegment('product');
        var brand = nvgGetSegment('brand');
        var connection = nvgGetSegment('connection');
        var career = nvgGetSegment('career');
        var everybuyer = nvgGetSegment('everybuyer');
        var custom = nvgGetSegment('custom');
        nvg_parms = (gender +';'+ age +';'+ education +';'+ marital +';'+ income +';'+ everyone +';'+  city +';'+ region +';'+  country +';'+ interest +';'+ product +';'+ brand +';'+ connection+';'+ career+';'+ everybuyer +';'+ custom);   

        if (location.href.indexOf("banco.bradesco") > -1) {
            $.post(Protocolo + "//wscampanhas.bradesco/wsRemarketingDigitalNew/api/WebDadosAdd/AddCorrentista", { Agencia: pAgencia, ContaDigito: pContaDigito, UA: pUA, URL: pUrl, Tecnologia: pTecnologia, TrackNavegg : nvg_parms, CPF : cpf  }).done(function (data1) { }).fail(function (data2) { console.log(data2); });
        } else {
            $.post(Protocolo + "//" + Global.TranslateAddress("wspf.bradesco.com.br") + "/wsRemarketingDigitalNew/api/WebDadosAdd/AddCorrentista", 
            	{   
            		Agencia: pAgencia, 
            		ContaDigito: pContaDigito, 
            		UA: pUA, 
            		URL: pUrl, 
            		Tecnologia:	pTecnologia, 
            		CPF : cpf ,
            		TrackNavegg : nvg_parms
            			 
            	}).done(function (data1) { }).fail(function (data2) 
            	{ 
            		console.log(data2); 
            	});
        }

	}
}