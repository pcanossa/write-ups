var Protocolo =  location.protocol;

/* INICIO - IP PARA GEOLOCALIZACAO */
if (typeof ipcli === 'undefined' || ipcli === null) {
    var ipcli = '<!--#echo var="REMOTE_ADDR"-->'
}
/* FIM - IP PARA GEOLOCALIZACAO */

/* INICIO - LOG DE NAVEGACAO */
if (typeof arrLog === 'undefined' || arrLog === null) {
    var arrLog = "";
}
/* FIM - LOG DE NAVEGACAO */

/* INICIO - VARIAVEIS PARA CAMPANHAS */
var home_classic = false;
var ref_emprestimos_e_financiamentos = false;
var ref_capitalizacao = false;

var agconta_retornoglobal = '';
var seg_global;
var camp_global;
var agcontaglobal = getCookie('bra_iscli');
/* FIM - VARIAVEIS PARA CAMPANHAS */

function ValidaNextAgencia(agNext){
    if(agNext=="3750") {
        alert('Informações inválidas. Por favor, verifique agência, conta e dígito.');
        $("#AGN").val('').focus();
    }
}

/* INICIO - funcao para criar, recuperar e deletar valores em cookies */
function setCookie(cname, cvalue, exdays) {
    var d = new Date();
    d.setTime(d.getTime() + (exdays * 24 * 60 * 60 * 1000));
    var expires = "expires=" + d.toGMTString();
    document.cookie = cname + "=" + cvalue + "; " + expires + "; path=/";
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

function deleteCookie(name) {
  document.cookie = name + '=; expires=Thu, 01 Jan 1970 00:00:01 GMT;';
}
/* FIM - funcao para criar, recuperar e deletar valores em cookies */


/* INICIO - Recuperar Query String Parameters */
function getURLparameters(name) {
    name = name.replace(/[\[]/, "\\\[").replace(/[\]]/, "\\\]");
    var regexS = "[\\?&]" + name + "=([^&#]*)";
    var regex = new RegExp(regexS);
    var results = regex.exec(window.location.href);

    if (results == null) {
        return "";
    } else {
        return results[1];
    }
}
/* FIM - Recuperar Query String Parameters */

/* INICIO - LOG DE NAVEGACAO (COM DATA) */
function logaNavegacaoComData(complement) {
    var cookie_track_name = 'bra_nav_track_dt';
    var bra_nav_track_dt = getCookie(cookie_track_name);

    // limpando o caminho atual retirando query strings para nao "sujar" a metrica.
    var now = new Date();
    var year = '0' + now.getFullYear();
    var month = '0' + (now.getMonth() + 1);
    var day = '0' + now.getDate();
    var hours = '0' + now.getHours();
    var minutes = '0' + now.getMinutes();
    var seconds = '0' + now.getSeconds();
    var ts = year.substr(year.length - 4, 4) + month.substr(month.length - 2, 2) + day.substr(day.length - 2, 2) + hours.substr(hours.length - 2, 2) + minutes.substr(minutes.length - 2, 2) + seconds.substr(seconds.length - 2, 2);
    var string_timestamp = '[' + ts + ']';

    var sHref = string_timestamp + location.href;
    var idx_qs = sHref.indexOf('?');
    if (idx_qs > -1) {
        sHref = sHref.substr(0, idx_qs);
    }

    if (complement != '') {
        sHref = sHref + '#' + complement;
    }

    var new_cookie_val = bra_nav_track_dt;

    if (new_cookie_val == '') {
        new_cookie_val = sHref;
        setCookie(cookie_track_name, new_cookie_val, 30);
    } else {
        arrLog = new_cookie_val.split("|");

        if (arrLog.length < 20) {
            new_cookie_val = new_cookie_val + "|" + sHref;
        } else {
            var idx_aux = new_cookie_val.indexOf('|');
            new_cookie_val = new_cookie_val.substr(idx_aux + 1, new_cookie_val.length);
            new_cookie_val = new_cookie_val + "|" + sHref;
        }

        setCookie(cookie_track_name, new_cookie_val, 30);
    }
}
/* FIM - LOG DE NAVEGACAO (COM DATA) */

/* INICIO - consulta hash MD5*/
function setHasMD5(ag,ct,dig){

    //Verifica agencia quando for chamada por modal
    if(ag != undefined){Gerabra_iscli(ag,ct,dig);}

    var agconta = getCookie('bra_iscli');
    var hash = getCookie('Hash_MD5');
    var pAgencia = agconta.substring(31, 35);
    var pConta = agconta.substring(35, 42);
    var pdigito = agconta.substring(42, 43);

    pAgencia == "" ? pAgencia = ag : pAgencia;
    pConta == "" ? pConta = ct : pConta;
    pdigito == "" ? pdigito = dig : pdigito;

    if (agconta.length > 0 && hash.length === 0 && VerificaLoginHash(pAgencia,pConta,pdigito)) {
         $.post(Protocolo + '//' +  Global.TranslateAddress("wspf.bradesco.com.br") + "/cragcc/api/criptografar", {
         Agencia: pAgencia, Conta: pConta
         }).done(function (data1) {
            hash = data1;
            setCookie('Hash_MD5', hash, 30);
            trackHash(hash);
         }
         ).fail(function (data2) {
           console.log(data2);
         });
    }
}
function trackHash(hash){
    ga('set', 'userId', hash);
    ga('set', 'dimension3', hash);
    trackBradesco('Hash MD5', 'userId', 'G.A com hash MD5', {nonInteraction: 1});
    setNaveggOndoarding(hash);
}
/*  FIM  - consulta hash MD5*/

// Gera agconta quando for chamado por modal
function Gerabra_iscli(cAG,cCON,cDIG){
    var agcon = "";

    if (cAG.length > 0 && cCON.length > 0 && cDIG.length > 0) {
        while (cAG.length < 4) {
        cAG = "0" + cAG;
    }
        while (cCON.length < 7) {
        cCON = "0" + cCON;
    }

    var now = new Date();
    var year = '0' + now.getFullYear();
    var month = '0' + (now.getMonth() + 1);
    var day = '0' + now.getDate();
    var hours = '0' + now.getHours();
    var minutes = '0' + now.getMinutes();
    var seconds = '0' + now.getSeconds();
    var ts = year.substr(year.length - 4, 4) + month.substr(month.length - 2, 2) + day.substr(day.length - 2, 2) + 'T' + hours.substr(hours.length - 2, 2) + minutes.substr(minutes.length - 2, 2) + seconds.substr(seconds.length - 2, 2);

        agcon = ts + "340989028374908D" + cAG + cCON + cDIG + "D982347509832745098324750923847";
        setCookie('bra_iscli', agcon, 30);
        setCookie('Hash_MD5',"",30);
    }
}
function VerificaLoginHash(pagencia, pConta, pdigito) {

    var valor = true;
    var Agencia = pagencia;
    var Conta = pConta;
    var Digito =  pdigito

    if ((isNaN(Agencia) == true) || (isNaN(Conta) == true) || (isNaN(Digito) == true))
    { valor = false; }
    else
    {
        if (ValidaDigitoHash(Conta,Digito) == true)
        { valor = true; }
        else
        { valor = false; }
    }
    return valor;
}
function ValidaDigitoHash(Conta,Digito) {
    //formAtual = PegaForm(campo.id);
    var lsoma = 0;
    var ipeso = 2;
    var dv_informado = Digito;
    var dv_conta = Conta;
    var tam = dv_conta.length;

    //Cria uma array
    var conta = new Array(tam);

    //Desmembra o array
    for (i = 0; i <= tam; i++)
    { conta[i] = dv_conta.substr(i, 1); }

    while (tam > 0) {
        digito = conta[--tam];
        if ((digito >= 0) && (digito <= 9)) {
            lsoma = lsoma + (digito - 0) * ipeso;
            ipeso = ipeso + 1;
            if (ipeso > 7)
            { ipeso = 2; }
        }
    }

    lsoma %= 11;
    lsoma = 11 - lsoma;

    if ((lsoma == 11) || (lsoma == 10)) {
        lsoma = 0;
    }

    return (parseInt(dv_informado) == parseInt(lsoma));
}
/* INICIO - LOG DE NAVEGACAO */
function logaNavegacaoServer() {

    var agconta = getCookie('bra_iscli');

    if (agconta.length > 0) {
        var pAgencia = agconta.substring(31, 35);
        var pContaDigito = agconta.substring(35, 43);
        var pUA = navigator.userAgent;
        var pUrl = window.location.href;
        var pTecnologia = 1;
        var nvg_parms = '';

        var gender = nvgGetSegment('gender');
        var age = nvgGetSegment('age');
        var education = nvgGetSegment('education');
        var marital = nvgGetSegment('marital');
        var income = nvgGetSegment('income');
        var everyone = nvgGetSegment('everyone');
        var city = nvgGetSegment('city');
        var region = nvgGetSegment('region');
        var country = nvgGetSegment('country');

        // criterio multi-valorados:
        var interest = nvgGetSegment('interest');
        var product = nvgGetSegment('product');
        var brand = nvgGetSegment('brand');
        var connection = nvgGetSegment('connection');
        var career = nvgGetSegment('career');
        var everybuyer = nvgGetSegment('everybuyer');
        var custom = nvgGetSegment('custom');
        nvg_parms = (gender +';'+ age +';'+ education +';'+ marital +';'+ income +';'+ everyone +';'+  city +';'+ region +';'+  country +';'+ interest +';'+ product +';'+ brand +';'+ connection+';'+ career+';'+ everybuyer +';'+ custom);

            if (location.href.indexOf("banco.bradesco") > -1) {
                $.post("https://wscampanhas.bradesco/wsRemarketingDigitalNew/api/WebDadosAdd/AddNaveg",
                    {
                        Agencia: pAgencia,
                        ContaDigito: pContaDigito,
                        UA: pUA,
                        URL: pUrl,
                        Tecnologia: pTecnologia,
                        TrackNavegg : nvg_parms
                    }).done(function (data1) {

                    }).fail(function (data2) {
                        console.log(data2);
                    });

            }
            // else {
            //     $.post("https://" + Global.TranslateAddress("wspf.bradesco.com.br") + "/wsRemarketingDigitalNew/api/WebDadosAdd/AddNaveg",
            //         {
            //             Agencia: pAgencia,
            //             ContaDigito: pContaDigito,
            //             UA: pUA,
            //             URL: pUrl,
            //             Tecnologia: pTecnologia,
            //             TrackNavegg : nvg_parms
            //         }).done(function (data1) { }).fail(function (data2) { console.log(data2); });
            // }
        }
}
/* FIM - LOG DE NAVEGACAO */

function EnviaInformacaoLimeWeb(agconta, escolha, campanha) {
    var url = ''

    if (location.href.indexOf("banco.bradesco") > -1) {
        url = "https://" + Global.TranslateAddress("wspf.bradesco.com.br") + "/wsRemarketing/CampaignCode.aspx?AgenciaConta=" + agconta + "&CampaignCode=" + campanha + "&Choice=" + escolha;
    } else {
         url = Protocolo + '//' +  Global.TranslateAddress("wspf.bradesco.com.br") + "/wsRemarketing/CampaignCode.aspx?AgenciaConta=" + agconta + "&CampaignCode=" + campanha + "&Choice=" + escolha;
    }

    if (ipcli.indexOf('10.') > -1) {
        if (navigator.userAgent.toLowerCase().indexOf('msie 9.0') > -1 || navigator.userAgent.toLowerCase().indexOf('msie 8.0') > -1 || navigator.userAgent.toLowerCase().indexOf('msie 7.0') > -1) {
            var timeout = 3000;
            if (window.XDomainRequest) {
                xdr = new XDomainRequest();
                if (xdr) {
                    xdr.open("GET", url);
                }
            }
        } else {
            if (window.XMLHttpRequest) {
                var Loader = new XMLHttpRequest();
                Loader.open("GET", url, false);
                Loader.send(null);

            } else if (window.ActiveXObject) {
                var Loader = new ActiveXObject("Msxml2.DOMDocument.3.0");
                Loader.load(url);
            }
        }
    } else if (window.XMLHttpRequest) {
        var Loader = new XMLHttpRequest();
        Loader.open("GET", url, false);
        Loader.send(null);

    } else if (window.ActiveXObject) {
        var Loader = new ActiveXObject("Msxml2.DOMDocument.3.0");
        Loader.load(url);
    }
}

function abreCampanhaAnimada(segretorno, camp) {
    console.log('abreCampanhaAnimada', segretorno, camp);
}

/* Funcao usada para setar a campanha quando feita com Base de clientes */
function setStatCampanhaBase(cmp, ag, conta, desc) {

    var basePathXML = "";
    var protocolo = location.protocol;
    basePathXML = protocolo + "//" + Global.TranslateAddress("wspf.bradesco.com.br") + "/wsstats/";


    var agencia = ag;
    var conta = conta;
    var url = null;

    if (location.search.indexOf('gclid') > 0) {
        url = 'LP(gclid=' + request.getParameter('gclid') + ')';
    }
    else {
        url = location.pathname;
    }
    if (desc == null) {
        basePathXML = basePathXML + "?stragencia=" + agencia + "&strconta=" + conta + "&cmp=" + cmp + "&urls=" + url;
    }
    else {
        basePathXML = basePathXML + "?stragencia=" + agencia + "&strconta=" + conta + "&cmp=" + cmp + "&urls=" + url + "&desc=" + desc;
    }
    if (window.XDomainRequest) {
        loadIE();
    } else {
        xml = loadXML(basePathXML);
    }
}
function loadXML(url) {

    if (window.XMLHttpRequest) {
        var Loader = new XMLHttpRequest();
        Loader.open("GET", url, false);
        Loader.send(null);
    } else if (window.ActiveXObject) {
        var Loader = new ActiveXObject("Msxml2.DOMDocument.3.0");
        Loader.async = false;
        Loader.load(url);
        return Loader;
    }
}

function loadIE() {
    var url = basePathXML;
    var timeout = 1000;
    if (window.XDomainRequest) {
        xdr = new XDomainRequest();
        if (xdr) {
            xdr.onerror = err;
            xdr.ontimeout = timeo;
            xdr.onprogress = progres;
            xdr.onload = loadd;
            xdr.timeout = timeout;
            xdr.open("get", url);
            xdr.send();
        }
    }
}
/* FIM - Funcao usada para setar a campanha */
function abreCampanhaPersonalizada(segretorno, camp, dadosCampanhaPersonalizada){

    setTimeout(function(){

        var context = 'classic';

        if (location.href.indexOf('/html/exclusive/') > -1) {
            context = 'exclusive';
        } else if (location.href.indexOf('/html/prime/') > -1) {
            context = 'prime';
        } else if (location.href.indexOf('/html/classic/') > -1) {
            context = 'classic';
        }

        switch(camp) {

            case "231004":
                if(location.href.indexOf('/html/classic/index.shtm') > -1 || location.href.indexOf('/html/exclusive/index.shtm') > -1 || location.href.indexOf('/html/prime/index.shtm') > -1) {


                    /*peace=1 exclusive  e peace=2 prime */
                   if(segretorno == 'EXCLUSIVE' || segretorno == 'exclusive')  {
                        img = "/assets/classic/img/retargeting/intervencao-lime-exclusive.jpg";
                    } if(segretorno == 'PRIME'  || segretorno == 'prime') {
                        img = "/assets/classic/img/retargeting/intervencao-lime-prime.jpg";
                    } if(segretorno == 'CLASSIC'  || segretorno == 'classic') {
                        img = "/assets/classic/img/retargeting/intervencao-lime-classic.jpg";
                    }

                    cookie_ref = dadosCampanhaPersonalizada.cookie_ref;
                    track_ref = parseInt(getCookie(cookie_ref + '_num')) || 0;


                    {

                        $.magnificPopup.open({
                            items: {
                                src: '/assets/common/inc/modalRetargeting.shtm',
                                type: 'ajax'
                            },
                            enableEscapeKey: false,
                            closeOnBgClick: false,
                            showCloseBtn: false,
                            callbacks: {
                                parseAjax: function (mfpResponse) {
                                    var style = 'background: url(' + img + ') center no-repeat;' + ' width: ' + dadosCampanhaPersonalizada.imagem.largura + 'px; height: ' + dadosCampanhaPersonalizada.imagem.altura + 'px;';
                                    mfpResponse.data = $(mfpResponse.data).attr('style', style);

                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('style', dadosCampanhaPersonalizada.botoes.classic.acessar.estilo);
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('style', dadosCampanhaPersonalizada.botoes.classic.verdepois.estilo);
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('style', dadosCampanhaPersonalizada.botoes.classic.fechar.estilo);


                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('title', dadosCampanhaPersonalizada.botoes.classic.acessar.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('href', '/assets/common/inc/modalIB.shtm');
                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').on('click', function() {
                                        $.magnificPopup.close();
                                        EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'A30', '231004');
                                        trackBradesco('Intervencao', dadosCampanhaPersonalizada.descricao + ' ' + segretorno, dadosCampanhaPersonalizada.botoes.classic.acessar.nome);
                                    });


                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('title', dadosCampanhaPersonalizada.botoes.classic.verdepois.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('href', '#');
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').on('click', function() {
                                        $.magnificPopup.close();
                                        EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'C53', '231004');
                                        setCookie(cookie_ref + '_num', (track_ref+1), dadosCampanhaPersonalizada.tmp_exibicao);
                                        trackBradesco('Intervencao', dadosCampanhaPersonalizada.descricao + ' ' + segretorno, dadosCampanhaPersonalizada.botoes.classic.verdepois.nome);

                                    });


                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('title', dadosCampanhaPersonalizada.botoes.classic.fechar.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('href', '#');
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').on('click', function() {
                                        $.magnificPopup.close();
                                        EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'C16', '231004');
                                        setCookie(cookie_ref + '_num', (track_ref+1), dadosCampanhaPersonalizada.tmp_exibicao);
                                        trackBradesco('Intervencao', dadosCampanhaPersonalizada.descricao + ' ' + segretorno, dadosCampanhaPersonalizada.botoes.classic.fechar.nome);
                                    });

                                },
                                ajaxContentAdded: function() {
                                    $('#lnk-rmkt-acessar').on('click', function(e) {
                                        $.magnificPopup.open({
                                            items: {
                                                src: this.href.replace(/^.*\/\/[^\/]+/, ''),
                                                type: 'ajax'
                                            },
                                            enableEscapeKey: false,
                                            closeOnBgClick: false,
                                            callbacks: {
                                                parseAjax: function (mfpResponse) {
                                                    mfpResponse.data = $(mfpResponse.data).removeClass('mfp-hide');

                                                    $(mfpResponse.data).find('input.btn.ok').on('click', function() {
                                                        var agconta = getCookie('bra_iscli');
                                                        var seg_agconta = getCookie('bra_segcli');
                                                        var agcon = "";

                                                        var cAG = $(this).parents('form').children().find('input[name=AGN]').val();
                                                        var cCON = $(this).parents('form').children().find('input[name=CTA]').val();
                                                        var cDIG = $(this).parents('form').children().find('input[name=DIGCTA]').val();

                                                        if (cAG.length > 0 && cCON.length > 0 && cDIG.length > 0) {
                                                            while (cAG.length < 4) {
                                                                cAG = "0" + cAG;
                                                            }

                                                            while (cCON.length < 7) {
                                                                cCON = "0" + cCON;
                                                            }

                                                            var now = new Date();
                                                            var year = '0' + now.getFullYear();
                                                            var month = '0' + (now.getMonth() + 1);
                                                            var day = '0' + now.getDate();
                                                            var hours = '0' + now.getHours();
                                                            var minutes = '0' + now.getMinutes();
                                                            var seconds = '0' + now.getSeconds();
                                                            var ts = year.substr(year.length - 4, 4) + month.substr(month.length - 2, 2) + day.substr(day.length - 2, 2) + 'T' + hours.substr(hours.length - 2, 2) + minutes.substr(minutes.length - 2, 2) + seconds.substr(seconds.length - 2, 2);

                                                            agcon = ts + "340989028374908D" + cAG + cCON + cDIG + "D982347509832745098324750923847";

                                                            setCookie('bra_iscli', agcon, 30);
                                                            setCookie(cookie_ref + '_num', num_exibicoes, tmp_exibicao);
                                                        }
                                                    });
                                                    //$(mfpResponse.data).find('input[name=ORIGEM]').val('804');
                                                    $(mfpResponse.data).find('input[name=CDSERVICO]').val('163');
                                                    trackModalAcoesGeral(context,"RT_Investimento");
                                                    trackModalSimule(context);

                                                }
                                            }
                                        });

                                        e.preventDefault;
                                        return false;
                                    });
                                }
                            }
                        });
                    }
                }

            break;

            case "230601":
                if(location.href.indexOf('/html/classic/index.shtm') > -1 || location.href.indexOf('/html/exclusive/index.shtm') > -1 || location.href.indexOf('/html/prime/index.shtm') > -1 ) {

                    /*peace=1 exclusive  e peace=2 prime  e peace=3 classic */
                    if(segretorno == 'EXCLUSIVE' || segretorno == 'exclusive')  {
                        img = "/assets/classic/img/retargeting/intervencao-lime-IB-exclusive.jpg";
                    }else if(segretorno == 'CLASSIC'  || segretorno == 'classic') {
                        img = "/assets/classic/img/retargeting/intervencao-lime-IB-classic.jpg";
                    }else if(segretorno == 'PRIME'  || segretorno == 'prime') {
                        img = "/assets/classic/img/retargeting/intervencao-lime-IB-prime.jpg";
                    }

                    cookie_ref = dadosCampanhaPersonalizada.cookie_ref;
                    track_ref = parseInt(getCookie(cookie_ref + '_num')) || 0;


                    {

                        $.magnificPopup.open({
                            items: {
                                src: '/assets/common/inc/modalRetargeting.shtm',
                                type: 'ajax'
                            },
                            enableEscapeKey: false,
                            closeOnBgClick: false,
                            showCloseBtn: false,
                            callbacks: {
                                parseAjax: function (mfpResponse) {
                                    var style = 'background: url(' + img + ') center no-repeat;' + ' width: ' + dadosCampanhaPersonalizada.imagem.largura + 'px; height: ' + dadosCampanhaPersonalizada.imagem.altura + 'px;';
                                    mfpResponse.data = $(mfpResponse.data).attr('style', style);

                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('style', dadosCampanhaPersonalizada.botoes.classic.acessar.estilo);
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('style', dadosCampanhaPersonalizada.botoes.classic.verdepois.estilo);
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('style', dadosCampanhaPersonalizada.botoes.classic.fechar.estilo);


                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('title', dadosCampanhaPersonalizada.botoes.classic.acessar.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('href', '/assets/common/inc/modalIB.shtm');
                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').on('click', function() {
                                        $.magnificPopup.close();
                                        EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'A30', '230601');
                                        trackBradesco('Intervencao', dadosCampanhaPersonalizada.descricao + ' ' + segretorno, dadosCampanhaPersonalizada.botoes.classic.acessar.nome);
                                    });


                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('title', dadosCampanhaPersonalizada.botoes.classic.verdepois.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('href', '#');
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').on('click', function() {
                                    $.magnificPopup.close();
                                        EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'C53', '230601');
                                        setCookie(cookie_ref + '_num', (track_ref+1), dadosCampanhaPersonalizada.tmp_exibicao);
                                        trackBradesco('Intervencao', dadosCampanhaPersonalizada.descricao + ' ' + segretorno, dadosCampanhaPersonalizada.botoes.classic.verdepois.nome);
                                    });


                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('title', dadosCampanhaPersonalizada.botoes.classic.fechar.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('href', '#');
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').on('click', function() {
                                        $.magnificPopup.close();
                                        EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'C16', '230601');
                                        setCookie(cookie_ref + '_num', (track_ref+1), dadosCampanhaPersonalizada.tmp_exibicao);
                                        trackBradesco('Intervencao', dadosCampanhaPersonalizada.descricao + ' ' + segretorno, dadosCampanhaPersonalizada.botoes.classic.fechar.nome);
                                    });


                                },
                                ajaxContentAdded: function() {
                                    $('#lnk-rmkt-acessar').on('click', function(e) {
                                        $.magnificPopup.open({
                                            items: {
                                                src: this.href.replace(/^.*\/\/[^\/]+/, ''),
                                                type: 'ajax'
                                            },
                                            enableEscapeKey: false,
                                            closeOnBgClick: false,
                                            callbacks: {
                                                parseAjax: function (mfpResponse) {
                                                    mfpResponse.data = $(mfpResponse.data).removeClass('mfp-hide');

                                                    $(mfpResponse.data).find('input.btn.ok').on('click', function() {
                                                        var agconta = getCookie('bra_iscli');
                                                        var seg_agconta = getCookie('bra_segcli');
                                                        var agcon = "";

                                                        var cAG = $(this).parents('form').children().find('input[name=AGN]').val();
                                                        var cCON = $(this).parents('form').children().find('input[name=CTA]').val();
                                                        var cDIG = $(this).parents('form').children().find('input[name=DIGCTA]').val();

                                                        if (cAG.length > 0 && cCON.length > 0 && cDIG.length > 0) {
                                                            while (cAG.length < 4) {
                                                                cAG = "0" + cAG;
                                                            }

                                                            while (cCON.length < 7) {
                                                                cCON = "0" + cCON;
                                                            }

                                                            var now = new Date();
                                                            var year = '0' + now.getFullYear();
                                                            var month = '0' + (now.getMonth() + 1);
                                                            var day = '0' + now.getDate();
                                                            var hours = '0' + now.getHours();
                                                            var minutes = '0' + now.getMinutes();
                                                            var seconds = '0' + now.getSeconds();
                                                            var ts = year.substr(year.length - 4, 4) + month.substr(month.length - 2, 2) + day.substr(day.length - 2, 2) + 'T' + hours.substr(hours.length - 2, 2) + minutes.substr(minutes.length - 2, 2) + seconds.substr(seconds.length - 2, 2);

                                                            agcon = ts + "340989028374908D" + cAG + cCON + cDIG + "D982347509832745098324750923847";

                                                            setCookie('bra_iscli', agcon, 30);
                                                            setCookie(cookie_ref + '_num', num_exibicoes, tmp_exibicao);
                                                        }
                                                    });
                                                        var origem = "";
                                                       if(location.href.indexOf('/html/classic/index.shtm') > -1 ){
                                                            origem = 101;
                                                       }else if (location.href.indexOf('/html/exclusive/index.shtm') > -1 ) {
                                                            origem = 84;
                                                       }else{
                                                            origem = 57;
                                                        }

                                                    $(mfpResponse.data).find('input[name=ORIGEM]').val(origem);
                                                    $(mfpResponse.data).find('input[name=CDSERVICO]').val(186);// Seguro viagem
                                                    trackModalConsig(context);

                                                }
                                            }
                                        });

                                        e.preventDefault;
                                        return false;
                                    });
                                }
                            }
                        });
                    }
                }

            break;

            case "231023":
                if(location.href.indexOf('/html/classic/index.shtm') > -1 || location.href.indexOf('/html/exclusive/index.shtm') > -1 || location.href.indexOf('/html/prime/index.shtm') > -1) {


                      /*peace=1 exclusive  e peace=2 prime  e peace=3 classic */
                   if(segretorno == 'EXCLUSIVE' || segretorno == 'exclusive')  {
                        img = "/assets/classic/img/retargeting/intervencao_consignado_EXCLUSIVE_01.jpg";
                    } if(segretorno == 'CLASSIC'  || segretorno == 'classic') {
                        img = "/assets/classic/img/retargeting/intervencao_consignado_Classic_01.jpg";
                    } if(segretorno == 'PRIME'  || segretorno == 'prime') {
                        img = "/assets/classic/img/retargeting/intervencao_consignado_PRIME_01.jpg";
                    }

                    cookie_ref = dadosCampanhaPersonalizada.cookie_ref;
                    track_ref = parseInt(getCookie(cookie_ref + '_num')) || 0;


                    {

                        $.magnificPopup.open({
                            items: {
                                src: '/assets/common/inc/modalRetargeting.shtm',
                                type: 'ajax'
                            },
                            enableEscapeKey: false,
                            closeOnBgClick: false,
                            showCloseBtn: false,
                            callbacks: {
                                parseAjax: function (mfpResponse) {
                                    var style = 'background: url(' + img + ') center no-repeat;' + ' width: ' + dadosCampanhaPersonalizada.imagem.largura + 'px; height: ' + dadosCampanhaPersonalizada.imagem.altura + 'px;';
                                    mfpResponse.data = $(mfpResponse.data).attr('style', style);

                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('style', dadosCampanhaPersonalizada.botoes.classic.acessar.estilo);
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('style', dadosCampanhaPersonalizada.botoes.classic.verdepois.estilo);
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('style', dadosCampanhaPersonalizada.botoes.classic.fechar.estilo);


                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('title', dadosCampanhaPersonalizada.botoes.classic.acessar.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('href', '/assets/common/inc/modalIB.shtm');
                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').on('click', function() {
                                       $.magnificPopup.close();
                                       EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'A30', '231023');
                                       trackBradesco('Intervencao', segretorno + "_consignado", dadosCampanhaPersonalizada.botoes.classic.acessar.nome);
                                    });


                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('title', dadosCampanhaPersonalizada.botoes.classic.verdepois.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('href', '#');
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').on('click', function() {
                                        $.magnificPopup.close();
                                        EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'C53', '231023');
                                        setCookie(cookie_ref + '_num', (track_ref+1), dadosCampanhaPersonalizada.tmp_exibicao);
                                        trackBradesco('Intervencao', segretorno + "_consignado", dadosCampanhaPersonalizada.botoes.classic.verdepois.nome);
                                    });


                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('title', dadosCampanhaPersonalizada.botoes.classic.fechar.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('href', '#');
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').on('click', function() {
                                       $.magnificPopup.close();
                                       EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'C16', '231023');
                                       setCookie(cookie_ref + '_num', (track_ref+1), dadosCampanhaPersonalizada.tmp_exibicao);
                                       trackBradesco('Intervencao', segretorno + "_consignado", dadosCampanhaPersonalizada.botoes.classic.fechar.nome);
                                    });


                                },
                                ajaxContentAdded: function() {
                                    $('#lnk-rmkt-acessar').on('click', function(e) {
                                        $.magnificPopup.open({
                                            items: {
                                                src: this.href.replace(/^.*\/\/[^\/]+/, ''),
                                                type: 'ajax'
                                            },
                                            enableEscapeKey: false,
                                            closeOnBgClick: false,
                                            callbacks: {
                                                parseAjax: function (mfpResponse) {
                                                    mfpResponse.data = $(mfpResponse.data).removeClass('mfp-hide');

                                                    $(mfpResponse.data).find('input.btn.ok').on('click', function() {
                                                        var agconta = getCookie('bra_iscli');
                                                        var seg_agconta = getCookie('bra_segcli');
                                                        var agcon = "";

                                                        var cAG = $(this).parents('form').children().find('input[name=AGN]').val();
                                                        var cCON = $(this).parents('form').children().find('input[name=CTA]').val();
                                                        var cDIG = $(this).parents('form').children().find('input[name=DIGCTA]').val();

                                                        if (cAG.length > 0 && cCON.length > 0 && cDIG.length > 0) {
                                                            while (cAG.length < 4) {
                                                                cAG = "0" + cAG;
                                                            }

                                                            while (cCON.length < 7) {
                                                                cCON = "0" + cCON;
                                                            }

                                                            var now = new Date();
                                                            var year = '0' + now.getFullYear();
                                                            var month = '0' + (now.getMonth() + 1);
                                                            var day = '0' + now.getDate();
                                                            var hours = '0' + now.getHours();
                                                            var minutes = '0' + now.getMinutes();
                                                            var seconds = '0' + now.getSeconds();
                                                            var ts = year.substr(year.length - 4, 4) + month.substr(month.length - 2, 2) + day.substr(day.length - 2, 2) + 'T' + hours.substr(hours.length - 2, 2) + minutes.substr(minutes.length - 2, 2) + seconds.substr(seconds.length - 2, 2);

                                                            agcon = ts + "340989028374908D" + cAG + cCON + cDIG + "D982347509832745098324750923847";

                                                            setCookie('bra_iscli', agcon, 30);
                                                            setCookie(cookie_ref + '_num', num_exibicoes, tmp_exibicao);
                                                        }
                                                    });
                                                        var origem = "";
                                                       if(location.href.indexOf('/html/classic/index.shtm') > -1 ){
                                                            origem = 101;
                                                       }else if (location.href.indexOf('/html/exclusive/index.shtm') > -1 ) {
                                                            origem = 84;
                                                       }else{
                                                            origem = 57;
                                                        }

                                                    $(mfpResponse.data).find('input[name=ORIGEM]').val(origem);
                                                    $(mfpResponse.data).find('input[name=CDSERVICO]').val(167);//  Consignado
                                                    trackModalConsig(context);

                                                }
                                            }
                                        });

                                        e.preventDefault;
                                        return false;
                                    });
                                }
                            }
                        });
                    }
                }

            break;

            case "231024":
                if(location.href.indexOf('/html/classic/index.shtm') > -1 || location.href.indexOf('/html/exclusive/index.shtm') > -1 || location.href.indexOf('/html/prime/index.shtm') > -1) {


                    /*peace=1 exclusive  e peace=2 prime  e peace=3 classic */
                   if(segretorno == 'EXCLUSIVE' || segretorno == 'exclusive')  {
                        img = "/assets/classic/img/retargeting/intervencao_consignado_EXCLUSIVE_01.jpg";
                    } if(segretorno == 'CLASSIC'  || segretorno == 'classic') {
                        img = "/assets/classic/img/retargeting/intervencao_consignado_Classic_01.jpg";
                    } if(segretorno == 'PRIME'  || segretorno == 'prime') {
                        img = "/assets/classic/img/retargeting/intervencao_consignado_PRIME_01.jpg";
                    }

                    cookie_ref = dadosCampanhaPersonalizada.cookie_ref;
                    track_ref = parseInt(getCookie(cookie_ref + '_num')) || 0;


                    {

                        $.magnificPopup.open({
                            items: {
                                src: '/assets/common/inc/modalRetargeting.shtm',
                                type: 'ajax'
                            },
                            enableEscapeKey: false,
                            closeOnBgClick: false,
                            showCloseBtn: false,
                            callbacks: {
                                parseAjax: function (mfpResponse) {
                                    var style = 'background: url(' + img + ') center no-repeat;' + ' width: ' + dadosCampanhaPersonalizada.imagem.largura + 'px; height: ' + dadosCampanhaPersonalizada.imagem.altura + 'px;';
                                    mfpResponse.data = $(mfpResponse.data).attr('style', style);

                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('style', dadosCampanhaPersonalizada.botoes.classic.acessar.estilo);
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('style', dadosCampanhaPersonalizada.botoes.classic.verdepois.estilo);
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('style', dadosCampanhaPersonalizada.botoes.classic.fechar.estilo);


                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('title', dadosCampanhaPersonalizada.botoes.classic.acessar.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('href', '/assets/common/inc/modalIB.shtm');
                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').on('click', function() {
                                       $.magnificPopup.close();
                                       EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'A30', '231024');
                                       trackBradesco('Intervencao', segretorno + "_consignado", dadosCampanhaPersonalizada.botoes.classic.acessar.nome);

                                    });


                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('title', dadosCampanhaPersonalizada.botoes.classic.verdepois.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('href', '#');
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').on('click', function() {
                                        $.magnificPopup.close();
                                        EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'C53', '231024');
                                        setCookie(cookie_ref + '_num', (track_ref+1), dadosCampanhaPersonalizada.tmp_exibicao);
                                        trackBradesco('Intervencao', segretorno + "_consignado", dadosCampanhaPersonalizada.botoes.classic.verdepois.nome);
                                    });


                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('title', dadosCampanhaPersonalizada.botoes.classic.fechar.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('href', '#');
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').on('click', function() {
                                        $.magnificPopup.close();
                                        EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'C16', '231024');
                                        setCookie(cookie_ref + '_num', (track_ref+1), dadosCampanhaPersonalizada.tmp_exibicao);
                                        trackBradesco('Intervencao', segretorno + "_consignado", dadosCampanhaPersonalizada.botoes.classic.fechar.nome);
                                    });


                                },
                                ajaxContentAdded: function() {
                                    $('#lnk-rmkt-acessar').on('click', function(e) {
                                        $.magnificPopup.open({
                                            items: {
                                                src: this.href.replace(/^.*\/\/[^\/]+/, ''),
                                                type: 'ajax'
                                            },
                                            enableEscapeKey: false,
                                            closeOnBgClick: false,
                                            callbacks: {
                                                parseAjax: function (mfpResponse) {
                                                    mfpResponse.data = $(mfpResponse.data).removeClass('mfp-hide');

                                                    $(mfpResponse.data).find('input.btn.ok').on('click', function() {
                                                        var agconta = getCookie('bra_iscli');
                                                        var seg_agconta = getCookie('bra_segcli');
                                                        var agcon = "";

                                                        var cAG = $(this).parents('form').children().find('input[name=AGN]').val();
                                                        var cCON = $(this).parents('form').children().find('input[name=CTA]').val();
                                                        var cDIG = $(this).parents('form').children().find('input[name=DIGCTA]').val();

                                                        if (cAG.length > 0 && cCON.length > 0 && cDIG.length > 0) {
                                                            while (cAG.length < 4) {
                                                                cAG = "0" + cAG;
                                                            }

                                                            while (cCON.length < 7) {
                                                                cCON = "0" + cCON;
                                                            }

                                                            var now = new Date();
                                                            var year = '0' + now.getFullYear();
                                                            var month = '0' + (now.getMonth() + 1);
                                                            var day = '0' + now.getDate();
                                                            var hours = '0' + now.getHours();
                                                            var minutes = '0' + now.getMinutes();
                                                            var seconds = '0' + now.getSeconds();
                                                            var ts = year.substr(year.length - 4, 4) + month.substr(month.length - 2, 2) + day.substr(day.length - 2, 2) + 'T' + hours.substr(hours.length - 2, 2) + minutes.substr(minutes.length - 2, 2) + seconds.substr(seconds.length - 2, 2);

                                                            agcon = ts + "340989028374908D" + cAG + cCON + cDIG + "D982347509832745098324750923847";

                                                            setCookie('bra_iscli', agcon, 30);
                                                            setCookie(cookie_ref + '_num', num_exibicoes, tmp_exibicao);
                                                        }
                                                    });
                                                        var origem = "";
                                                       if(location.href.indexOf('/html/classic/index.shtm') > -1 ){
                                                            origem = 101;
                                                       }else if (location.href.indexOf('/html/exclusive/index.shtm') > -1 ) {
                                                            origem = 84;
                                                       }else{
                                                            origem = 57;
                                                        }

                                                    $(mfpResponse.data).find('input[name=ORIGEM]').val(origem);
                                                    $(mfpResponse.data).find('input[name=CDSERVICO]').val(167);// Consignadom
                                                    trackModalConsig(context);

                                                }
                                            }
                                        });

                                        e.preventDefault;
                                        return false;
                                    });
                                }
                            }
                        });
                    }
                }

            break;

            case "230402": //Investimentos
                if(location.href.indexOf('/html/classic/index.shtm') > -1 || location.href.indexOf('/html/exclusive/index.shtm') > -1 || location.href.indexOf('/html/prime/index.shtm') > -1) {

                    /*peace=1 exclusive  e peace=2 prime  e peace=3 classic */
                   if(segretorno == 'EXCLUSIVE' || segretorno == 'exclusive')  {
                        img = "/assets/classic/img/retargeting/Invest_Facil_Entretela_Exclusive.jpg";
                    } if(segretorno == 'CLASSIC'  || segretorno == 'classic') {
                        img = "/assets/classic/img/retargeting/Invest_Facil_Entretela_Classic.jpg";
                    } if(segretorno == 'PRIME'  || segretorno == 'prime') {
                        img = "/assets/classic/img/retargeting/Invest_Facil_Entretela_Prime.jpg";
                    }

                    cookie_ref = dadosCampanhaPersonalizada.cookie_ref;
                    track_ref = parseInt(getCookie(cookie_ref + '_num')) || 0;

                    {

                        $.magnificPopup.open({
                            items: {
                                src: '/assets/common/inc/modalRetargeting.shtm',
                                type: 'ajax'
                            },
                            enableEscapeKey: false,
                            closeOnBgClick: false,
                            showCloseBtn: false,
                            callbacks: {
                                parseAjax: function (mfpResponse) {
                                    var style = 'background: url(' + img + ') center no-repeat;' + ' width: ' + dadosCampanhaPersonalizada.imagem.largura + 'px; height: ' + dadosCampanhaPersonalizada.imagem.altura + 'px;';
                                    mfpResponse.data = $(mfpResponse.data).attr('style', style);

                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('style', dadosCampanhaPersonalizada.botoes.classic.acessar.estilo);
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('style', dadosCampanhaPersonalizada.botoes.classic.verdepois.estilo);
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('style', dadosCampanhaPersonalizada.botoes.classic.fechar.estilo);


                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('title', dadosCampanhaPersonalizada.botoes.classic.acessar.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('href', '/assets/common/inc/modalIB.shtm');
                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').on('click', function() {
                                       $.magnificPopup.close();
                                       EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'A30', '230402');
                                       trackBradesco('Intervencao', segretorno + "_Investimento", dadosCampanhaPersonalizada.botoes.classic.acessar.nome);
                                    });


                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('title', dadosCampanhaPersonalizada.botoes.classic.verdepois.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('href', '#');
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').on('click', function() {
                                        $.magnificPopup.close();
                                        EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'C53', '230402');
                                        setCookie(cookie_ref + '_num', (track_ref+1), dadosCampanhaPersonalizada.tmp_exibicao);
                                        trackBradesco('Intervencao', segretorno + "_Investimento", dadosCampanhaPersonalizada.botoes.classic.verdepois.nome);
                                    });


                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('title', dadosCampanhaPersonalizada.botoes.classic.fechar.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('href', '#');
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').on('click', function() {
                                        $.magnificPopup.close();
                                        EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'C16', '230402');
                                        setCookie(cookie_ref + '_num', (track_ref+1), dadosCampanhaPersonalizada.tmp_exibicao);
                                        trackBradesco('Intervencao', segretorno + "_Investimento", dadosCampanhaPersonalizada.botoes.classic.fechar.nome);
                                    });


                                },
                                ajaxContentAdded: function() {
                                    $('#lnk-rmkt-acessar').on('click', function(e) {
                                        $.magnificPopup.open({
                                            items: {
                                                src: this.href.replace(/^.*\/\/[^\/]+/, ''),
                                                type: 'ajax'
                                            },
                                            enableEscapeKey: false,
                                            closeOnBgClick: false,
                                            callbacks: {
                                                parseAjax: function (mfpResponse) {
                                                    mfpResponse.data = $(mfpResponse.data).removeClass('mfp-hide');

                                                    $(mfpResponse.data).find('input.btn.ok').on('click', function() {
                                                        var agconta = getCookie('bra_iscli');
                                                        var seg_agconta = getCookie('bra_segcli');
                                                        var agcon = "";

                                                        var cAG = $(this).parents('form').children().find('input[name=AGN]').val();
                                                        var cCON = $(this).parents('form').children().find('input[name=CTA]').val();
                                                        var cDIG = $(this).parents('form').children().find('input[name=DIGCTA]').val();

                                                        if (cAG.length > 0 && cCON.length > 0 && cDIG.length > 0) {
                                                            while (cAG.length < 4) {
                                                                cAG = "0" + cAG;
                                                            }

                                                            while (cCON.length < 7) {
                                                                cCON = "0" + cCON;
                                                            }

                                                            var now = new Date();
                                                            var year = '0' + now.getFullYear();
                                                            var month = '0' + (now.getMonth() + 1);
                                                            var day = '0' + now.getDate();
                                                            var hours = '0' + now.getHours();
                                                            var minutes = '0' + now.getMinutes();
                                                            var seconds = '0' + now.getSeconds();
                                                            var ts = year.substr(year.length - 4, 4) + month.substr(month.length - 2, 2) + day.substr(day.length - 2, 2) + 'T' + hours.substr(hours.length - 2, 2) + minutes.substr(minutes.length - 2, 2) + seconds.substr(seconds.length - 2, 2);

                                                            agcon = ts + "340989028374908D" + cAG + cCON + cDIG + "D982347509832745098324750923847";

                                                            setCookie('bra_iscli', agcon, 30);
                                                            setCookie(cookie_ref + '_num', num_exibicoes, tmp_exibicao);
                                                        }
                                                    });

                                                    $(mfpResponse.data).find('input[name=CDSERVICO]').val('174'); // Investimento
                                                    $(mfpResponse.data).find('span.title').text('Contrate Agora');
                                                    trackModalAcoesGeral(context,"RT_Investimento");

                                                }
                                            }
                                        });

                                        e.preventDefault;
                                        return false;
                                    });
                                }
                            }
                        });
                    }
                }

            break;

            case "230105":  //Acao_Seguros_Debito
                if(location.href.indexOf('/html/classic/index.shtm') > -1 || location.href.indexOf('/html/exclusive/index.shtm') > -1 ) {


                    /*peace=1 exclusive  e peace=2 prime  e peace=3 classic */
                    if(segretorno == 'EXCLUSIVE' || segretorno == 'exclusive')  {
                        img = "/assets/classic/img/retargeting/Entretela_Exclusive.jpg";
                    } if(segretorno == 'CLASSIC'  || segretorno == 'classic') {
                        img = "/assets/classic/img/retargeting/Entretela_Classic.jpg";
                    }

                    cookie_ref = dadosCampanhaPersonalizada.cookie_ref;
                    track_ref = parseInt(getCookie(cookie_ref + '_num')) || 0;


                    {

                        $.magnificPopup.open({
                            items: {
                                src: '/assets/common/inc/modalRetargeting.shtm',
                                type: 'ajax'
                            },
                            enableEscapeKey: false,
                            closeOnBgClick: false,
                            showCloseBtn: false,
                            callbacks: {
                                parseAjax: function (mfpResponse) {
                                    var style = 'background: url(' + img + ') center no-repeat;' + ' width: ' + dadosCampanhaPersonalizada.imagem.largura + 'px; height: ' + dadosCampanhaPersonalizada.imagem.altura + 'px;';
                                    mfpResponse.data = $(mfpResponse.data).attr('style', style);

                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('style', dadosCampanhaPersonalizada.botoes.classic.acessar.estilo);
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('style', dadosCampanhaPersonalizada.botoes.classic.verdepois.estilo);
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('style', dadosCampanhaPersonalizada.botoes.classic.fechar.estilo);


                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('title', dadosCampanhaPersonalizada.botoes.classic.acessar.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('href', '/assets/common/inc/modalIB.shtm');
                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('onclick', "trackBradesco('Intervencao','" + segretorno + '_' + dadosCampanhaPersonalizada.descricao + "','" + dadosCampanhaPersonalizada.botoes.classic.acessar.nome + "');");
                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').on('click', function() {
                                        $.magnificPopup.close();
                                        EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'A30', '230105');
                                        trackBradesco('Intervencao', segretorno + '_' + dadosCampanhaPersonalizada.descricao, dadosCampanhaPersonalizada.botoes.classic.acessar.nome);
                                    });


                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('title', dadosCampanhaPersonalizada.botoes.classic.verdepois.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('href', '#');
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('onclick', "trackBradesco('Intervencao','" + segretorno + '_' + dadosCampanhaPersonalizada.descricao + "','" + dadosCampanhaPersonalizada.botoes.classic.verdepois.nome + "');");
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').on('click', function() {
                                        $.magnificPopup.close();
                                        EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'C53', '230105');
                                        setCookie(cookie_ref + '_num', (track_ref+1), dadosCampanhaPersonalizada.tmp_exibicao);
                                        trackBradesco('Intervencao', segretorno + '_' + dadosCampanhaPersonalizada.descricao, dadosCampanhaPersonalizada.botoes.classic.verdepois.nome);

                                    });


                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('title', dadosCampanhaPersonalizada.botoes.classic.fechar.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('href', '#');
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('onclick', "trackBradesco('Intervencao','" + segretorno + '_' + dadosCampanhaPersonalizada.descricao + "','" + dadosCampanhaPersonalizada.botoes.classic.fechar.nome + "');");
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').on('click', function() {
                                        $.magnificPopup.close();
                                        EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'C16', '230105');
                                        setCookie(cookie_ref + '_num', (track_ref+1), dadosCampanhaPersonalizada.tmp_exibicao);
                                        trackBradesco('Intervencao', segretorno + '_' + dadosCampanhaPersonalizada.descricao, dadosCampanhaPersonalizada.botoes.classic.fechar.nome);
                                    });


                                },
                                ajaxContentAdded: function() {
                                    $('#lnk-rmkt-acessar').on('click', function(e) {
                                        $.magnificPopup.open({
                                            items: {
                                                src: this.href.replace(/^.*\/\/[^\/]+/, ''),
                                                type: 'ajax'
                                            },
                                            enableEscapeKey: false,
                                            closeOnBgClick: false,
                                            callbacks: {
                                                parseAjax: function (mfpResponse) {
                                                    mfpResponse.data = $(mfpResponse.data).removeClass('mfp-hide');

                                                    $(mfpResponse.data).find('input.btn.ok').on('click', function() {
                                                        var agconta = getCookie('bra_iscli');
                                                        var seg_agconta = getCookie('bra_segcli');
                                                        var agcon = "";

                                                        var cAG = $(this).parents('form').children().find('input[name=AGN]').val();
                                                        var cCON = $(this).parents('form').children().find('input[name=CTA]').val();
                                                        var cDIG = $(this).parents('form').children().find('input[name=DIGCTA]').val();

                                                        if (cAG.length > 0 && cCON.length > 0 && cDIG.length > 0) {
                                                            while (cAG.length < 4) {
                                                                cAG = "0" + cAG;
                                                            }

                                                            while (cCON.length < 7) {
                                                                cCON = "0" + cCON;
                                                            }

                                                            var now = new Date();
                                                            var year = '0' + now.getFullYear();
                                                            var month = '0' + (now.getMonth() + 1);
                                                            var day = '0' + now.getDate();
                                                            var hours = '0' + now.getHours();
                                                            var minutes = '0' + now.getMinutes();
                                                            var seconds = '0' + now.getSeconds();
                                                            var ts = year.substr(year.length - 4, 4) + month.substr(month.length - 2, 2) + day.substr(day.length - 2, 2) + 'T' + hours.substr(hours.length - 2, 2) + minutes.substr(minutes.length - 2, 2) + seconds.substr(seconds.length - 2, 2);

                                                            agcon = ts + "340989028374908D" + cAG + cCON + cDIG + "D982347509832745098324750923847";

                                                            setCookie('bra_iscli', agcon, 30);
                                                            setCookie(cookie_ref + '_num', num_exibicoes, tmp_exibicao);
                                                        }
                                                    });

                                                    var origem = "";
                                                    var extraparams = "";
                                                    var cdservico = "";
                                                    if(location.href.indexOf('/html/classic/index.shtm') > -1 ){
                                                        origem = dadosCampanhaPersonalizada.transacional.classic.origem;
                                                        extraparams = dadosCampanhaPersonalizada.transacional.classic.extraparams;
                                                        cdservico = dadosCampanhaPersonalizada.transacional.classic.cdservico;
                                                    }else if (location.href.indexOf('/html/exclusive/index.shtm') > -1 ) {
                                                        origem = dadosCampanhaPersonalizada.transacional.exclusive.origem;
                                                        extraparams = dadosCampanhaPersonalizada.transacional.exclusive.extraparams;
                                                        cdservico = dadosCampanhaPersonalizada.transacional.exclusive.cdservico;
                                                    }else{
                                                        origem = dadosCampanhaPersonalizada.transacional.prime.origem;
                                                        extraparams = dadosCampanhaPersonalizada.transacional.prime.extraparams;
                                                        cdservico = dadosCampanhaPersonalizada.transacional.prime.cdservico;
                                                    }

                                                    $(mfpResponse.data).find('input[name=ORIGEM]').val(origem);
                                                    $(mfpResponse.data).find('input[name=EXTRAPARAMS]').val(extraparams);
                                                    $(mfpResponse.data).find('input[name=CDSERVICO]').val(cdservico);
                                                    trackModalAcoesGeral(segretorno,dadosCampanhaPersonalizada.descricao);

                                                }
                                            }
                                        });

                                        e.preventDefault;
                                        return false;
                                    });
                                }
                            }
                        });
                    }
                }

            break;

            case "230603":  //Acao_Seguros_Familia
                if(location.href.indexOf('/html/classic/index.shtm') > -1 || location.href.indexOf('/html/exclusive/index.shtm') > -1 ) {


                    /*peace=1 exclusive  e peace=2 prime  e peace=3 classic */
                    if(segretorno == 'EXCLUSIVE' || segretorno == 'exclusive')  {
                        img = "/assets/classic/img/retargeting/Enrtretela_IB_APP_Exclusive.jpg";
                    } if(segretorno == 'CLASSIC'  || segretorno == 'classic') {
                        img = "/assets/classic/img/retargeting/Enrtretela_IB_APP_Classic.jpg";
                    }

                    cookie_ref = dadosCampanhaPersonalizada.cookie_ref;
                    track_ref = parseInt(getCookie(cookie_ref + '_num')) || 0;


                    {

                        $.magnificPopup.open({
                            items: {
                                src: '/assets/common/inc/modalRetargeting.shtm',
                                type: 'ajax'
                            },
                            enableEscapeKey: false,
                            closeOnBgClick: false,
                            showCloseBtn: false,
                            callbacks: {
                                parseAjax: function (mfpResponse) {
                                    var style = 'background: url(' + img + ') center no-repeat;' + ' width: ' + dadosCampanhaPersonalizada.imagem.largura + 'px; height: ' + dadosCampanhaPersonalizada.imagem.altura + 'px;';
                                    mfpResponse.data = $(mfpResponse.data).attr('style', style);

                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('style', dadosCampanhaPersonalizada.botoes.classic.acessar.estilo);
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('style', dadosCampanhaPersonalizada.botoes.classic.verdepois.estilo);
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('style', dadosCampanhaPersonalizada.botoes.classic.fechar.estilo);


                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('title', dadosCampanhaPersonalizada.botoes.classic.acessar.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('href', '/assets/common/inc/modalIB.shtm');
                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('onclick', "trackBradesco('Intervencao','" + segretorno + '_' + dadosCampanhaPersonalizada.descricao + "','" + dadosCampanhaPersonalizada.botoes.classic.acessar.nome + "');");
                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').on('click', function() {
                                        $.magnificPopup.close();
                                        EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'A30', '230603');
                                        trackBradesco('Intervencao', segretorno + '_' + dadosCampanhaPersonalizada.descricao, dadosCampanhaPersonalizada.botoes.classic.acessar.nome);
                                    });


                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('title', dadosCampanhaPersonalizada.botoes.classic.verdepois.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('href', '#');
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('onclick', "trackBradesco('Intervencao','" + segretorno + '_' + dadosCampanhaPersonalizada.descricao + "','" + dadosCampanhaPersonalizada.botoes.classic.verdepois.nome + "');");
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').on('click', function() {
                                        $.magnificPopup.close();
                                        EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'C53', '230603');
                                        setCookie(cookie_ref + '_num', (track_ref+1), dadosCampanhaPersonalizada.tmp_exibicao);
                                        trackBradesco('Intervencao', segretorno + '_' + dadosCampanhaPersonalizada.descricao, dadosCampanhaPersonalizada.botoes.classic.verdepois.nome);
                                    });


                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('title', dadosCampanhaPersonalizada.botoes.classic.fechar.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('href', '#');
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('onclick', "trackBradesco('Intervencao','" + segretorno + '_' + dadosCampanhaPersonalizada.descricao + "','" + dadosCampanhaPersonalizada.botoes.classic.fechar.nome + "');");
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').on('click', function() {
                                        $.magnificPopup.close();
                                        EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'C16', '230603');
                                        setCookie(cookie_ref + '_num', (track_ref+1), dadosCampanhaPersonalizada.tmp_exibicao);
                                        trackBradesco('Intervencao', segretorno + '_' + dadosCampanhaPersonalizada.descricao, dadosCampanhaPersonalizada.botoes.classic.fechar.nome);
                                    });


                                },
                                ajaxContentAdded: function() {
                                    $('#lnk-rmkt-acessar').on('click', function(e) {
                                        $.magnificPopup.open({
                                            items: {
                                                src: this.href.replace(/^.*\/\/[^\/]+/, ''),
                                                type: 'ajax'
                                            },
                                            enableEscapeKey: false,
                                            closeOnBgClick: false,
                                            callbacks: {
                                                parseAjax: function (mfpResponse) {
                                                    mfpResponse.data = $(mfpResponse.data).removeClass('mfp-hide');

                                                    $(mfpResponse.data).find('input.btn.ok').on('click', function() {
                                                        var agconta = getCookie('bra_iscli');
                                                        var seg_agconta = getCookie('bra_segcli');
                                                        var agcon = "";

                                                        var cAG = $(this).parents('form').children().find('input[name=AGN]').val();
                                                        var cCON = $(this).parents('form').children().find('input[name=CTA]').val();
                                                        var cDIG = $(this).parents('form').children().find('input[name=DIGCTA]').val();

                                                        if (cAG.length > 0 && cCON.length > 0 && cDIG.length > 0) {
                                                            while (cAG.length < 4) {
                                                                cAG = "0" + cAG;
                                                            }

                                                            while (cCON.length < 7) {
                                                                cCON = "0" + cCON;
                                                            }

                                                            var now = new Date();
                                                            var year = '0' + now.getFullYear();
                                                            var month = '0' + (now.getMonth() + 1);
                                                            var day = '0' + now.getDate();
                                                            var hours = '0' + now.getHours();
                                                            var minutes = '0' + now.getMinutes();
                                                            var seconds = '0' + now.getSeconds();
                                                            var ts = year.substr(year.length - 4, 4) + month.substr(month.length - 2, 2) + day.substr(day.length - 2, 2) + 'T' + hours.substr(hours.length - 2, 2) + minutes.substr(minutes.length - 2, 2) + seconds.substr(seconds.length - 2, 2);

                                                            agcon = ts + "340989028374908D" + cAG + cCON + cDIG + "D982347509832745098324750923847";

                                                            setCookie('bra_iscli', agcon, 30);
                                                            setCookie(cookie_ref + '_num', num_exibicoes, tmp_exibicao);
                                                        }
                                                    });

                                                    var origem = "";
                                                    var extraparams = "";
                                                    var cdservico = "";
                                                    if(location.href.indexOf('/html/classic/index.shtm') > -1 ){
                                                        origem = dadosCampanhaPersonalizada.transacional.classic.origem;
                                                        extraparams = dadosCampanhaPersonalizada.transacional.classic.extraparams;
                                                        cdservico = dadosCampanhaPersonalizada.transacional.classic.cdservico;
                                                    }else if (location.href.indexOf('/html/exclusive/index.shtm') > -1 ) {
                                                        origem = dadosCampanhaPersonalizada.transacional.exclusive.origem;
                                                        extraparams = dadosCampanhaPersonalizada.transacional.exclusive.extraparams;
                                                        cdservico = dadosCampanhaPersonalizada.transacional.exclusive.cdservico;
                                                    }else{
                                                        origem = dadosCampanhaPersonalizada.transacional.prime.origem;
                                                        extraparams = dadosCampanhaPersonalizada.transacional.prime.extraparams;
                                                        cdservico = dadosCampanhaPersonalizada.transacional.prime.cdservico;
                                                    }

                                                    $(mfpResponse.data).find('input[name=ORIGEM]').val(origem);
                                                    $(mfpResponse.data).find('input[name=EXTRAPARAMS]').val(extraparams);
                                                    $(mfpResponse.data).find('input[name=CDSERVICO]').val(cdservico);
                                                    trackModalAcoesGeral(segretorno,dadosCampanhaPersonalizada.descricao);

                                                }
                                            }
                                        });

                                        e.preventDefault;
                                        return false;
                                    });
                                }
                            }
                        });
                    }
                }

            break;

            case "230704": //Acao Capitalizacao
                if(location.href.indexOf('/html/classic/index.shtm') > -1 ) {


                    /*peace=1 exclusive  e peace=2 prime  e peace=3 classic */
                    img = "/assets/classic/img/retargeting/intervencao_capitalizacao.jpg";

                    cookie_ref = dadosCampanhaPersonalizada.cookie_ref;
                    track_ref = parseInt(getCookie(cookie_ref + '_num')) || 0;

                    {

                        $.magnificPopup.open({
                            items: {
                                src: '/assets/common/inc/modalRetargeting.shtm',
                                type: 'ajax'
                            },
                            enableEscapeKey: false,
                            closeOnBgClick: false,
                            showCloseBtn: false,
                            callbacks: {
                                parseAjax: function (mfpResponse) {
                                    var style = 'background: url(' + img + ') center no-repeat;' + ' width: ' + dadosCampanhaPersonalizada.imagem.largura + 'px; height: ' + dadosCampanhaPersonalizada.imagem.altura + 'px;';
                                    mfpResponse.data = $(mfpResponse.data).attr('style', style);

                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('style', dadosCampanhaPersonalizada.botoes.classic.acessar.estilo);
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('style', dadosCampanhaPersonalizada.botoes.classic.verdepois.estilo);
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('style', dadosCampanhaPersonalizada.botoes.classic.fechar.estilo);


                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('title', dadosCampanhaPersonalizada.botoes.classic.acessar.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('href', '/assets/common/inc/modalIB.shtm');
                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').on('click', function() {
                                        $.magnificPopup.close();
                                        EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'A30', '230704');
                                        trackBradesco('Intervencao', segretorno + "_Capitalizacao", dadosCampanhaPersonalizada.botoes.classic.acessar.nome);
                                    });


                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('title', dadosCampanhaPersonalizada.botoes.classic.verdepois.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('href', '#');
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').on('click', function() {
                                        $.magnificPopup.close();
                                        EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'C53', '230704');
                                        setCookie(cookie_ref + '_num', (track_ref+1), dadosCampanhaPersonalizada.tmp_exibicao);
                                        trackBradesco('Intervencao', segretorno + "_Capitalizacao", dadosCampanhaPersonalizada.botoes.classic.verdepois.nome);
                                    });


                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('title', dadosCampanhaPersonalizada.botoes.classic.fechar.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('href', '#');
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').on('click', function() {
                                        $.magnificPopup.close();
                                        EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'C16', '230704');
                                        setCookie(cookie_ref + '_num', (track_ref+1), dadosCampanhaPersonalizada.tmp_exibicao);
                                        trackBradesco('Intervencao', segretorno + "_Capitalizacao", dadosCampanhaPersonalizada.botoes.classic.fechar.nome);
                                    });


                                },
                                ajaxContentAdded: function() {
                                    $('#lnk-rmkt-acessar').on('click', function(e) {
                                        $.magnificPopup.open({
                                            items: {
                                                src: this.href.replace(/^.*\/\/[^\/]+/, ''),
                                                type: 'ajax'
                                            },
                                            enableEscapeKey: false,
                                            closeOnBgClick: false,
                                            callbacks: {
                                                parseAjax: function (mfpResponse) {
                                                    mfpResponse.data = $(mfpResponse.data).removeClass('mfp-hide');

                                                    $(mfpResponse.data).find('input.btn.ok').on('click', function() {
                                                        var agconta = getCookie('bra_iscli');
                                                        var seg_agconta = getCookie('bra_segcli');
                                                        var agcon = "";

                                                        var cAG = $(this).parents('form').children().find('input[name=AGN]').val();
                                                        var cCON = $(this).parents('form').children().find('input[name=CTA]').val();
                                                        var cDIG = $(this).parents('form').children().find('input[name=DIGCTA]').val();

                                                        if (cAG.length > 0 && cCON.length > 0 && cDIG.length > 0) {
                                                            while (cAG.length < 4) {
                                                                cAG = "0" + cAG;
                                                            }

                                                            while (cCON.length < 7) {
                                                                cCON = "0" + cCON;
                                                            }

                                                            var now = new Date();
                                                            var year = '0' + now.getFullYear();
                                                            var month = '0' + (now.getMonth() + 1);
                                                            var day = '0' + now.getDate();
                                                            var hours = '0' + now.getHours();
                                                            var minutes = '0' + now.getMinutes();
                                                            var seconds = '0' + now.getSeconds();
                                                            var ts = year.substr(year.length - 4, 4) + month.substr(month.length - 2, 2) + day.substr(day.length - 2, 2) + 'T' + hours.substr(hours.length - 2, 2) + minutes.substr(minutes.length - 2, 2) + seconds.substr(seconds.length - 2, 2);

                                                            agcon = ts + "340989028374908D" + cAG + cCON + cDIG + "D982347509832745098324750923847";

                                                            setCookie('bra_iscli', agcon, 30);
                                                            setCookie(cookie_ref + '_num', 4, tmp_exibicao);
                                                            setCookie('baixa_camp', true, dadosCampanhaPersonalizada.tmp_exibicao);
                                                        }
                                                    });
                                                        var origem = "";
                                                       if(location.href.indexOf('/html/classic/index.shtm') > -1 ){
                                                            origem = 101;
                                                       }else if (location.href.indexOf('/html/exclusive/index.shtm') > -1 ) {
                                                            origem = 84;
                                                       }else{
                                                            origem = 57;
                                                        }

                                                    $(mfpResponse.data).find('input[name=ORIGEM]').val(origem);
                                                    $(mfpResponse.data).find('input[name=CDSERVICO]').val(178);// Capitalizacao pe quente
                                                    $(mfpResponse.data).find('input[name=EXTRAPARAMS]').val(139);// extra parans
                                                    trackModalConsig(context);

                                                }
                                            }
                                        });

                                        e.preventDefault;
                                        return false;
                                    });
                                }
                            }
                        });
                    }
                }

            break;

            case "230616": //Seguro_Dental
               if(location.href.indexOf('/html/classic/index.shtm') > -1 || location.href.indexOf('/html/exclusive/index.shtm') > -1 ) {
                   var actualContext = segretorno.toLowerCase();

                    if(segretorno == 'EXCLUSIVE' || segretorno == 'exclusive')  {
                        img = "/assets/exclusive/img/retargeting/Intervencao_Seguro_Dental.jpg";
                    } if(segretorno == 'CLASSIC'  || segretorno == 'classic') {
                        img = "/assets/classic/img/retargeting/Intervencao_Seguro_Dental.jpg";
                    }

                    cookie_ref = dadosCampanhaPersonalizada.cookie_ref;
                    track_ref = parseInt(getCookie(cookie_ref + '_num')) || 0;

                    {

                        $.magnificPopup.open({
                            items: {
                                src: '/assets/common/inc/modalRetargeting.shtm',
                                type: 'ajax'
                            },
                            enableEscapeKey: false,
                            closeOnBgClick: false,
                            showCloseBtn: false,
                            callbacks: {
                                parseAjax: function (mfpResponse) {
                                    var style = 'background: url(' + img + ') center no-repeat;' + ' width: ' + dadosCampanhaPersonalizada.imagem.largura + 'px; height: ' + dadosCampanhaPersonalizada.imagem.altura + 'px;';
                                    mfpResponse.data = $(mfpResponse.data).attr('style', style);

                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('style', dadosCampanhaPersonalizada.botoes.classic.acessar.estilo);
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('style', dadosCampanhaPersonalizada.botoes.classic.verdepois.estilo);
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('style', dadosCampanhaPersonalizada.botoes.classic.fechar.estilo);


                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('title', dadosCampanhaPersonalizada.botoes.classic.acessar.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('href', '/assets/common/inc/modalIB.shtm');
                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').on('click', function() {
                                        $.magnificPopup.close();
                                        EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'A30', '230616');
                                        trackBradesco('Intervencao_RT', segretorno + "_SeguroDental", dadosCampanhaPersonalizada.botoes.classic.acessar.nome);
                                    });


                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('title', dadosCampanhaPersonalizada.botoes.classic.verdepois.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('href', '#');
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').on('click', function() {
                                        $.magnificPopup.close();
                                        EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'C53', '230616');
                                        setCookie(cookie_ref + '_num', (track_ref+1), dadosCampanhaPersonalizada.tmp_exibicao);
                                        trackBradesco('Intervencao_RT', segretorno + "_SeguroDental", dadosCampanhaPersonalizada.botoes.classic.verdepois.nome);
                                    });


                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('title', dadosCampanhaPersonalizada.botoes.classic.fechar.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('href', '#');
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').on('click', function() {
                                        $.magnificPopup.close();
                                        EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'C16', '230616');
                                        setCookie(cookie_ref + '_num', (track_ref+1), dadosCampanhaPersonalizada.tmp_exibicao);
                                        trackBradesco('Intervencao_RT', segretorno + "_SeguroDental", dadosCampanhaPersonalizada.botoes.classic.fechar.nome);
                                    });


                                },
                                ajaxContentAdded: function() {
                                    $('#lnk-rmkt-acessar').on('click', function(e) {
                                        $.magnificPopup.open({
                                            items: {
                                                src: this.href.replace(/^.*\/\/[^\/]+/, ''),
                                                type: 'ajax'
                                            },
                                            enableEscapeKey: false,
                                            closeOnBgClick: false,
                                            callbacks: {
                                                parseAjax: function (mfpResponse) {
                                                    mfpResponse.data = $(mfpResponse.data).removeClass('mfp-hide');

                                                    $(mfpResponse.data).find('input.btn.ok').on('click', function() {
                                                        var agconta = getCookie('bra_iscli');
                                                        var seg_agconta = getCookie('bra_segcli');
                                                        var agcon = "";

                                                        var cAG = $(this).parents('form').children().find('input[name=AGN]').val();
                                                        var cCON = $(this).parents('form').children().find('input[name=CTA]').val();
                                                        var cDIG = $(this).parents('form').children().find('input[name=DIGCTA]').val();

                                                        if (cAG.length > 0 && cCON.length > 0 && cDIG.length > 0) {
                                                            while (cAG.length < 4) {
                                                                cAG = "0" + cAG;
                                                            }

                                                            while (cCON.length < 7) {
                                                                cCON = "0" + cCON;
                                                            }

                                                            var now = new Date();
                                                            var year = '0' + now.getFullYear();
                                                            var month = '0' + (now.getMonth() + 1);
                                                            var day = '0' + now.getDate();
                                                            var hours = '0' + now.getHours();
                                                            var minutes = '0' + now.getMinutes();
                                                            var seconds = '0' + now.getSeconds();
                                                            var ts = year.substr(year.length - 4, 4) + month.substr(month.length - 2, 2) + day.substr(day.length - 2, 2) + 'T' + hours.substr(hours.length - 2, 2) + minutes.substr(minutes.length - 2, 2) + seconds.substr(seconds.length - 2, 2);

                                                            agcon = ts + "340989028374908D" + cAG + cCON + cDIG + "D982347509832745098324750923847";

                                                            setCookie('bra_iscli', agcon, 30);
                                                            setCookie(cookie_ref + '_num', 4, tmp_exibicao);
                                                            setCookie('baixa_camp', true, dadosCampanhaPersonalizada.tmp_exibicao);
                                                        }
                                                    });
                                                        var origem = "";
                                                       if(location.href.indexOf('/html/classic/index.shtm') > -1 ){
                                                            origem = 101;
                                                       }else if (location.href.indexOf('/html/exclusive/index.shtm') > -1 ) {
                                                            origem = 84;
                                                       }else{
                                                            origem = 57;
                                                        }

                                                    $(mfpResponse.data).find('input[name=ORIGEM]').val(origem);
                                                    $(mfpResponse.data).find('input[name=CDSERVICO]').val(187);// _SeguroDental
                                                    trackModalAcoesGeral(actualContext,dadosCampanhaPersonalizada.descricao);

                                                }
                                            }
                                        });

                                        e.preventDefault;
                                        return false;
                                    });
                                }
                            }
                        });
                    }
                }

            break;

            case "230617": // Bilhete_Residencial
                if(location.href.indexOf('/html/classic/index.shtm') > -1 || location.href.indexOf('/html/exclusive/index.shtm') > -1 || location.href.indexOf('/html/prime/index.shtm') > -1 ) {

                    var actualContext = segretorno.toLowerCase();
                    /*peace=1 exclusive  e peace=2 prime  e peace=3 classic */
                    if(segretorno == 'EXCLUSIVE' || segretorno == 'exclusive')  {
                        img = "/assets/exclusive/img/retargeting/intervencao_Bilhete_Residencial.jpg";
                    }else if(segretorno == 'CLASSIC'  || segretorno == 'classic') {
                        img = "/assets/classic/img/retargeting/intervencao_Bilhete_Residencial.jpg";
                    }else if(segretorno == 'PRIME'  || segretorno == 'prime') {
                        img = "/assets/prime/img/retargeting/intervencao_Bilhete_Residencial.jpg";
                    }

                    cookie_ref = dadosCampanhaPersonalizada.cookie_ref;
                    track_ref = parseInt(getCookie(cookie_ref + '_num')) || 0;


                    {

                        $.magnificPopup.open({
                            items: {
                                src: '/assets/common/inc/modalRetargeting.shtm',
                                type: 'ajax'
                            },
                            enableEscapeKey: false,
                            closeOnBgClick: false,
                            showCloseBtn: false,
                            callbacks: {
                                parseAjax: function (mfpResponse) {
                                    var style = 'background: url(' + img + ') center no-repeat;' + ' width: ' + dadosCampanhaPersonalizada.imagem.largura + 'px; height: ' + dadosCampanhaPersonalizada.imagem.altura + 'px;';
                                    mfpResponse.data = $(mfpResponse.data).attr('style', style);

                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('style', dadosCampanhaPersonalizada.botoes.classic.acessar.estilo);
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('style', dadosCampanhaPersonalizada.botoes.classic.verdepois.estilo);
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('style', dadosCampanhaPersonalizada.botoes.classic.fechar.estilo);


                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('title', dadosCampanhaPersonalizada.botoes.classic.acessar.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('href', '/assets/common/inc/modalIB.shtm');
                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').on('click', function() {
                                        $.magnificPopup.close();
                                        EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'A30', '230617');
                                        trackBradesco('Intervencao', dadosCampanhaPersonalizada.descricao + ' ' + segretorno, dadosCampanhaPersonalizada.botoes.classic.acessar.nome);
                                    });


                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('title', dadosCampanhaPersonalizada.botoes.classic.verdepois.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('href', '#');
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').on('click', function() {
                                    $.magnificPopup.close();
                                        EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'C53', '230617');
                                        setCookie(cookie_ref + '_num', (track_ref+1), dadosCampanhaPersonalizada.tmp_exibicao);
                                        trackBradesco('Intervencao', dadosCampanhaPersonalizada.descricao + ' ' + segretorno, dadosCampanhaPersonalizada.botoes.classic.verdepois.nome);
                                    });


                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('title', dadosCampanhaPersonalizada.botoes.classic.fechar.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('href', '#');
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').on('click', function() {
                                        $.magnificPopup.close();
                                        EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'C16', '230617');
                                        setCookie(cookie_ref + '_num', (track_ref+1), dadosCampanhaPersonalizada.tmp_exibicao);
                                        trackBradesco('Intervencao', dadosCampanhaPersonalizada.descricao + ' ' + segretorno, dadosCampanhaPersonalizada.botoes.classic.fechar.nome);
                                    });


                                },
                                ajaxContentAdded: function() {
                                    $('#lnk-rmkt-acessar').on('click', function(e) {
                                        $.magnificPopup.open({
                                            items: {
                                                src: this.href.replace(/^.*\/\/[^\/]+/, ''),
                                                type: 'ajax'
                                            },
                                            enableEscapeKey: false,
                                            closeOnBgClick: false,
                                            callbacks: {
                                                parseAjax: function (mfpResponse) {
                                                    mfpResponse.data = $(mfpResponse.data).removeClass('mfp-hide');

                                                    $(mfpResponse.data).find('input.btn.ok').on('click', function() {
                                                        var agconta = getCookie('bra_iscli');
                                                        var seg_agconta = getCookie('bra_segcli');
                                                        var agcon = "";

                                                        var cAG = $(this).parents('form').children().find('input[name=AGN]').val();
                                                        var cCON = $(this).parents('form').children().find('input[name=CTA]').val();
                                                        var cDIG = $(this).parents('form').children().find('input[name=DIGCTA]').val();

                                                        if (cAG.length > 0 && cCON.length > 0 && cDIG.length > 0) {
                                                            while (cAG.length < 4) {
                                                                cAG = "0" + cAG;
                                                            }

                                                            while (cCON.length < 7) {
                                                                cCON = "0" + cCON;
                                                            }

                                                            var now = new Date();
                                                            var year = '0' + now.getFullYear();
                                                            var month = '0' + (now.getMonth() + 1);
                                                            var day = '0' + now.getDate();
                                                            var hours = '0' + now.getHours();
                                                            var minutes = '0' + now.getMinutes();
                                                            var seconds = '0' + now.getSeconds();
                                                            var ts = year.substr(year.length - 4, 4) + month.substr(month.length - 2, 2) + day.substr(day.length - 2, 2) + 'T' + hours.substr(hours.length - 2, 2) + minutes.substr(minutes.length - 2, 2) + seconds.substr(seconds.length - 2, 2);

                                                            agcon = ts + "340989028374908D" + cAG + cCON + cDIG + "D982347509832745098324750923847";

                                                            setCookie('bra_iscli', agcon, 30);
                                                            setCookie(cookie_ref + '_num', num_exibicoes, tmp_exibicao);
                                                        }
                                                    });
                                                        var origem = "";
                                                       if(location.href.indexOf('/html/classic/index.shtm') > -1 ){
                                                            origem = 101;
                                                       }else if (location.href.indexOf('/html/exclusive/index.shtm') > -1 ) {
                                                            origem = 84;
                                                       }else{
                                                            origem = 57;
                                                        }

                                                    $(mfpResponse.data).find('input[name=ORIGEM]').val(origem);
                                                    $(mfpResponse.data).find('input[name=CDSERVICO]').val(189);// Bilhete_Residencial
                                                    trackModalAcoesGeral(actualContext,dadosCampanhaPersonalizada.descricao);

                                                }
                                            }
                                        });

                                        e.preventDefault;
                                        return false;
                                    });
                                }
                            }
                        });
                    }
                }

            break;

            case "230904": // Previdência_Aporte

                if(location.href.indexOf('/html/classic/index.shtm') > -1 || location.href.indexOf('/html/exclusive/index.shtm') > -1 || location.href.indexOf('/html/prime/index.shtm') > -1 ) {

                    var actualContext = segretorno.toLowerCase();
                    /*peace=1 exclusive  e peace=2 prime  e peace=3 classic */
                    if(segretorno == 'EXCLUSIVE' || segretorno == 'exclusive')  {
                        img = "/assets/exclusive/img/retargeting/intervencao_Previdencia_Aporte.jpg";
                    }else if(segretorno == 'CLASSIC'  || segretorno == 'classic') {
                        img = "/assets/classic/img/retargeting/intervencao_Previdencia_Aporte.jpg";
                    }else if(segretorno == 'PRIME'  || segretorno == 'prime') {
                        img = "/assets/prime/img/retargeting/intervencao_Previdencia_Aporte.jpg";
                    }

                    cookie_ref = dadosCampanhaPersonalizada.cookie_ref;
                    track_ref = parseInt(getCookie(cookie_ref + '_num')) || 0;


                    {

                        $.magnificPopup.open({
                            items: {
                                src: '/assets/common/inc/modalRetargeting.shtm',
                                type: 'ajax'
                            },
                            enableEscapeKey: false,
                            closeOnBgClick: false,
                            showCloseBtn: false,
                            callbacks: {
                                parseAjax: function (mfpResponse) {
                                    var style = 'background: url(' + img + ') center no-repeat;' + ' width: ' + dadosCampanhaPersonalizada.imagem.largura + 'px; height: ' + dadosCampanhaPersonalizada.imagem.altura + 'px;';
                                    mfpResponse.data = $(mfpResponse.data).attr('style', style);

                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('style', dadosCampanhaPersonalizada.botoes.classic.acessar.estilo);
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('style', dadosCampanhaPersonalizada.botoes.classic.verdepois.estilo);
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('style', dadosCampanhaPersonalizada.botoes.classic.fechar.estilo);


                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('title', dadosCampanhaPersonalizada.botoes.classic.acessar.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('href', '/assets/common/inc/modalIB.shtm');
                                    $(mfpResponse.data).find('#lnk-rmkt-acessar').on('click', function() {
                                        $.magnificPopup.close();
                                        EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'A30', '230904');
                                        trackBradesco('Intervencao', dadosCampanhaPersonalizada.descricao + ' ' + segretorno, dadosCampanhaPersonalizada.botoes.classic.acessar.nome);
                                    });


                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('title', dadosCampanhaPersonalizada.botoes.classic.verdepois.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('href', '#');
                                    $(mfpResponse.data).find('#lnk-rmkt-ver-depois').on('click', function() {
                                    $.magnificPopup.close();
                                        EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'C53', '230904');
                                        setCookie(cookie_ref + '_num', (track_ref+1), dadosCampanhaPersonalizada.tmp_exibicao);
                                        trackBradesco('Intervencao', dadosCampanhaPersonalizada.descricao + ' ' + segretorno, dadosCampanhaPersonalizada.botoes.classic.verdepois.nome);
                                    });


                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('title', dadosCampanhaPersonalizada.botoes.classic.fechar.nome);
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('href', '#');
                                    $(mfpResponse.data).find('#lnk-rmkt-fechar').on('click', function() {
                                        $.magnificPopup.close();
                                        EnviaInformacaoLimeWeb(getCookie('bra_iscli'), 'C16', '230904');
                                        setCookie(cookie_ref + '_num', (track_ref+1), dadosCampanhaPersonalizada.tmp_exibicao);
                                        trackBradesco('Intervencao', dadosCampanhaPersonalizada.descricao + ' ' + segretorno, dadosCampanhaPersonalizada.botoes.classic.fechar.nome);
                                    });


                                },
                                ajaxContentAdded: function() {
                                    $('#lnk-rmkt-acessar').on('click', function(e) {
                                        $.magnificPopup.open({
                                            items: {
                                                src: this.href.replace(/^.*\/\/[^\/]+/, ''),
                                                type: 'ajax'
                                            },
                                            enableEscapeKey: false,
                                            closeOnBgClick: false,
                                            callbacks: {
                                                parseAjax: function (mfpResponse) {
                                                    mfpResponse.data = $(mfpResponse.data).removeClass('mfp-hide');

                                                    $(mfpResponse.data).find('input.btn.ok').on('click', function() {
                                                        var agconta = getCookie('bra_iscli');
                                                        var seg_agconta = getCookie('bra_segcli');
                                                        var agcon = "";

                                                        var cAG = $(this).parents('form').children().find('input[name=AGN]').val();
                                                        var cCON = $(this).parents('form').children().find('input[name=CTA]').val();
                                                        var cDIG = $(this).parents('form').children().find('input[name=DIGCTA]').val();

                                                        if (cAG.length > 0 && cCON.length > 0 && cDIG.length > 0) {
                                                            while (cAG.length < 4) {
                                                                cAG = "0" + cAG;
                                                            }

                                                            while (cCON.length < 7) {
                                                                cCON = "0" + cCON;
                                                            }

                                                            var now = new Date();
                                                            var year = '0' + now.getFullYear();
                                                            var month = '0' + (now.getMonth() + 1);
                                                            var day = '0' + now.getDate();
                                                            var hours = '0' + now.getHours();
                                                            var minutes = '0' + now.getMinutes();
                                                            var seconds = '0' + now.getSeconds();
                                                            var ts = year.substr(year.length - 4, 4) + month.substr(month.length - 2, 2) + day.substr(day.length - 2, 2) + 'T' + hours.substr(hours.length - 2, 2) + minutes.substr(minutes.length - 2, 2) + seconds.substr(seconds.length - 2, 2);

                                                            agcon = ts + "340989028374908D" + cAG + cCON + cDIG + "D982347509832745098324750923847";

                                                            setCookie('bra_iscli', agcon, 30);
                                                            setCookie(cookie_ref + '_num', num_exibicoes, tmp_exibicao);
                                                        }
                                                    });
                                                        var origem = "";
                                                       if(location.href.indexOf('/html/classic/index.shtm') > -1 ){
                                                            origem = 101;
                                                       }else if (location.href.indexOf('/html/exclusive/index.shtm') > -1 ) {
                                                            origem = 84;
                                                       }else{
                                                            origem = 57;
                                                        }

                                                    $(mfpResponse.data).find('input[name=ORIGEM]').val(origem);
                                                    $(mfpResponse.data).find('input[name=CDSERVICO]').val(185);// Previdência_Aporte
                                                    trackModalAcoesGeral(actualContext,dadosCampanhaPersonalizada.descricao);

                                                }
                                            }
                                        });

                                        e.preventDefault;
                                        return false;
                                    });
                                }
                            }
                        });
                    }
                }

            break;

        } // switch

     }, 300); // FIM setTimeout 1 segundos = 1000

}// FIM abreCampanhaPersonalizada

function trackModalSimule(context){

    setTimeout(function(){
        $("#modalIB .mfp-close").attr("onclick", "trackBradesco('Intervencao','REALTIME " + context + ",'Modal_Fechar');");
        $("#modalIB #Form68 input[type='submit']").attr("onclick", "trackBradesco('Intervencao','REALTIME " + context + ",'Modal_OK'); btnOK();");
        $("#modalIB #Form68 .pdfmodal").attr("onclick", "trackBradesco('Intervencao','REALTIME " + context + ",'Modal_Confira_horarios_e_limites');");
        $("#modalIB .ncliente a").attr("onclick", "trackBradesco('Intervencao','REALTIME " + context + ",'Modal_Abra_sua_conta');");
     }, 1000);
}
function trackModalConsig(context){

    setTimeout(function(){
        $("#modalIB .mfp-close").attr("onclick", "trackBradesco('Intervencao'," + context + "_Consignado','Modal_Fechar');");
        $("#modalIB #Form68 input[type='submit']").attr("onclick", "trackBradesco('Intervencao'," + context + "_Consignado','Modal_OK'); btnOK();");
        $("#modalIB #Form68 .pdfmodal").attr("onclick", "trackBradesco('Intervencao'," + context + "_Consignado','Modal_Confira_horarios_e_limites');");
        $("#modalIB .ncliente a").attr("onclick", "trackBradesco('Intervencao'," + context + "_Consignado','Modal_Abra_sua_conta');");
     }, 1000);
}

function trackModalAcoesGeral(segmento,acao){
    setTimeout(function(){
        $("#modalIB .mfp-close").attr("onclick", "trackBradesco('Intervencao','" + segmento + "_" + acao + "','Modal_Fechar');");
        $("#modalIB #Form68 input[type='submit']").attr("onclick", "trackBradesco('Intervencao','" + segmento + "_" + acao + "','Modal_OK'); btnOK();");
        $("#modalIB #Form68 .pdfmodal").attr("onclick", "trackBradesco('Intervencao','" + segmento + "_" + acao + "','Modal_Confira_horarios_e_limites');");
        $("#modalIB .ncliente a").attr("onclick", "trackBradesco('Intervencao','" + segmento + "_" + acao + "','Modal_Abra_sua_conta');");
     }, 1000);
}

function trackModalCDCveiculos(context){
    setTimeout(function(){
        $("#modalIBCDC .mfp-close").attr("onclick", "trackBradesco('Intervencao','" + context + "_Captura_de_Leads','Botao_Fechar');");
        $("#modalIBCDC #form input").attr("onclick", "trackBradesco('Intervencao','" + context + "_Captura_de_Leads','Botao_enviar');");

     }, 1000);
}

function trackBannerAcoesGeral(segmento,acao,campanha,gconta){
       setTimeout(function(){
        $("#modalIB .mfp-close").attr("onclick", "trackBradesco('" + segmento  + "','" + acao + "','Modal_Fechar'); EnviaInformacaoSubHomeRT('" + gconta + "','B62','" + campanha  + "');");
        $("#modalIB #Form68 input[type='submit']").attr("onclick", "trackBradesco('" +  segmento + "','" + acao + "','Modal_OK'); EnviaInformacaoSubHomeRT('" + gconta + "','A30','" + campanha + "');");
        $("#modalIB #Form68 .pdfmodal").attr("onclick", "trackBradesco('" +  segmento + "','" + acao + "','Modal_Confira_horarios_e_limites');");
        $("#modalIB .ncliente a").attr("onclick", "trackBradesco('" +  segmento + "','" + acao + "','Modal_Abra_sua_conta');");
     }, 1000);
}

/* INICIO - FUNCIONALIDADES CAMPANHAS */
function setCampaignMultiCamp(retornoglobal) {
    if (agcontaglobal.length > 0) {
        agconta_retornoglobal = retornoglobal.split(",");
        if (agconta_retornoglobal.length > 0) {
            seg_global = agconta_retornoglobal[1];

           if(agconta_retornoglobal[1] === 'Peace=1'){
                seg_global = 'EXCLUSIVE';
            } else if(agconta_retornoglobal[1] ==='Peace=2'){
                seg_global = 'PRIME';
            } else if(agconta_retornoglobal[1] ==='Peace=3'){
                seg_global = 'CLASSIC';
            } else{
                seg_global = seg_global;
            }

            setCookie('bra_segcli', seg_global, 30);

            camp_global = agconta_retornoglobal[2];
            hash_global = agconta_retornoglobal[3];

            setCookie('bra_camp', camp_global, 30);

        } else {
            var seg_global = '';
            var camp_global = '';
            var hash_global = '';
        }
    }

    var retorno = agconta_retornoglobal[0] >= 1 ? true : false;
    var segretorno = seg_global.toLowerCase();
    var camp = camp_global;
    var datas = {};
    var arrTarget = [];
    var cookie_ref;
    var track_ref;
    var desc_camp;
    var img;
    var imgWidth;
    var imgHeight;
    var form_ref;
    var btn_acessar;
    var btn_verdepois;
    var btn_naoquero;
    var tit_modal_ag_conta;
    var transacional;
    var modal_ref;
    var modal_ib = true;
    var palco = false;
    var arrPalco = [];

    if (retorno) {
        $.getJSON("/assets/common/js/retargeting.json", {}).done(function(data) {
            var existe = false;
            $.each(data, function(index, campanhas) {
                $.each(campanhas, function(index, campanha) {
                    if (existe == false) {
                        existe = (index == camp);
                    }
                });

                if (existe && !campanhas[camp].personalizada) {
                    arrTarget = campanhas[camp].palcos.urls;
                    compTarget = campanhas[camp].palcos.comportamento;
                    cookie_ref = campanhas[camp].cookie_ref;
                    num_exibicoes = campanhas[camp].num_exibicoes;
                    tmp_exibicao = campanhas[camp].tmp_exibicao;
                    desc_camp = campanhas[camp].descricao;
                    img = "/assets/" + segretorno + "/img/retargeting/" + campanhas[camp].imagem.nome;
                    imgWidth = campanhas[camp].imagem.largura;
                    imgHeight = campanhas[camp].imagem.altura;
                    form_ref = campanhas[camp].form_ref;
                    btn_acessar = campanhas[camp].botoes[segretorno].acessar;
                    btn_verdepois = campanhas[camp].botoes[segretorno].verdepois;
                    btn_naoquero = campanhas[camp].botoes[segretorno].naoquero;
                    btn_fechar = campanhas[camp].botoes[segretorno].fechar;
                    tit_modal_ag_conta = campanhas[camp].titulo_modal;
                    transacional = campanhas[camp].transacional[segretorno];
                    modal_ref = campanhas[camp].modal.referencia;
                    modal_titulo = campanhas[camp].modal.titulo;
                    datas = campanhas[camp].datas;
                    campanhaAnimada = campanhas[camp].animada;
                    campanhaPersonalizada = false;
                } else {
                    if (existe && campanhas[camp].personalizada) {
                        campanhaPersonalizada = true;
                        dadosCampanhaPersonalizada = campanhas[camp];
                    }
                }
            });

            if (existe && !campanhaPersonalizada) {
                track_ref = parseInt(getCookie(cookie_ref + '_num')) || 0;

                /* INICIO - VERIFICA SE PAGINA ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â° PALCO */
                if (arrTarget.length == 0) {
                    palco = true;
                } else {
                    $.each(arrTarget, function(index, value) {
                        arrPalco.push((location.href.indexOf(value) > -1));
                    });

                    switch(compTarget) {
                        case "incluir":
                            if (arrPalco.indexOf(true) > -1) {
                                palco = true;
                            }
                        break;

                        case "excluir":
                            if (arrPalco.indexOf(true) > -1) {
                                palco = false;
                            } else {
                                palco = true;
                            }
                        break;
                    }
                }
                /* FIM - VERIFICA SE PAGINA ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â° PALCO */

                if (track_ref < num_exibicoes) {
                    if(palco) {
                        if(!campanhaAnimada) {
                            $.magnificPopup.open({
                                items: {
                                    src: modal_ref,
                                    type: 'ajax'
                                },
                                enableEscapeKey: false,
                                closeOnBgClick: false,
                                showCloseBtn: false,
                                callbacks: {
                                    parseAjax: function (mfpResponse) {

                                        btn_acessar.tracking.param1 = (btn_acessar.tracking.param1 == "") ? "Intervencao" : btn_acessar.tracking.param1;
                                        btn_acessar.tracking.param2 = (btn_acessar.tracking.param2 == "") ? desc_camp + " " + segretorno : btn_acessar.tracking.param2;
                                        btn_acessar.tracking.param3 = (btn_acessar.tracking.param3 == "") ? btn_acessar.nome : btn_acessar.tracking.param3;

                                        btn_verdepois.tracking.param1 = (btn_verdepois.tracking.param1 == "") ? "Intervencao" : btn_verdepois.tracking.param1;
                                        btn_verdepois.tracking.param2 = (btn_verdepois.tracking.param2 == "") ? desc_camp + " " + segretorno : btn_verdepois.tracking.param2;
                                        btn_verdepois.tracking.param3 = (btn_verdepois.tracking.param3 == "") ? btn_verdepois.nome : btn_verdepois.tracking.param3;

                                        btn_fechar.tracking.param1 = (btn_fechar.tracking.param1 == "") ? "Intervencao" : btn_fechar.tracking.param1;
                                        btn_fechar.tracking.param2 = (btn_fechar.tracking.param2 == "") ? desc_camp + " " + segretorno : btn_fechar.tracking.param2;
                                        btn_fechar.tracking.param3 = (btn_fechar.tracking.param3 == "") ? btn_fechar.nome : btn_fechar.tracking.param3;

                                        btn_naoquero.tracking.param1 = (btn_naoquero.tracking.param1 == "") ? "Intervencao" : btn_naoquero.tracking.param1;
                                        btn_naoquero.tracking.param2 = (btn_naoquero.tracking.param2 == "") ? desc_camp + " " + segretorno : btn_naoquero.tracking.param2;
                                        btn_naoquero.tracking.param3 = (btn_naoquero.tracking.param3 == "") ? btn_naoquero.nome : btn_naoquero.tracking.param3;

                                        var style = 'background: url(' + img + ') center no-repeat;' + ' width: ' + imgWidth + 'px; height: ' + imgHeight + 'px;';
                                        mfpResponse.data = $(mfpResponse.data).attr('style', style);

                                        $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('style', btn_acessar.estilo);
                                        $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('title', btn_acessar.nome);
                                        $(mfpResponse.data).find('#lnk-rmkt-acessar').attr('href', btn_acessar.referencia);
                                        $(mfpResponse.data).find('#lnk-rmkt-acessar').on('click', function() {
                                            trackBradesco(btn_acessar.tracking.param1, btn_acessar.tracking.param2, btn_acessar.tracking.param3);
                                            $.magnificPopup.close();
                                        });

                                        $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('style', btn_verdepois.estilo);
                                        $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('title', btn_verdepois.nome);
                                        $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('href', btn_verdepois.referencia);
                                        $(mfpResponse.data).find('#lnk-rmkt-ver-depois').on('click', function() {
                                            trackBradesco(btn_verdepois.tracking.param1, btn_verdepois.tracking.param2, btn_verdepois.tracking.param3);
                                            setCookie(cookie_ref + '_num', (track_ref+1), tmp_exibicao);
                                            // setCookie('acesso_dia', 1,1);
                                            $.magnificPopup.close();
                                        });

                                        $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('style', btn_fechar.estilo);
                                        $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('title', btn_fechar.nome);
                                        $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('href', btn_fechar.referencia);
                                        $(mfpResponse.data).find('#lnk-rmkt-fechar').on('click', function() {
                                            trackBradesco(btn_fechar.tracking.param1, btn_fechar.tracking.param2, btn_fechar.tracking.param3);
                                            setCookie(cookie_ref + '_num', (track_ref+1), tmp_exibicao);
                                            // setCookie('avaliado', 2,360);
                                            $.magnificPopup.close();
                                        });

                                        $(mfpResponse.data).find('#lnk-rmkt-nao-quero').attr('style', btn_naoquero.estilo);
                                        $(mfpResponse.data).find('#lnk-rmkt-nao-quero').attr('title', btn_naoquero.nome);
                                        $(mfpResponse.data).find('#lnk-rmkt-nao-quero').attr('href', btn_naoquero.referencia);
                                        $(mfpResponse.data).find('#lnk-rmkt-nao-quero').on('click', function() {
                                            trackBradesco(btn_naoquero.tracking.param1, btn_naoquero.tracking.param2, btn_naoquero.tracking.param3);
                                            setCookie(cookie_ref + '_num', num_exibicoes, tmp_exibicao);
                                            $.magnificPopup.close();
                                        });

                                    },
                                    ajaxContentAdded: function() {
                                        if(modal_ib) {
                                            $('#lnk-rmkt-acessar').on('click', function(e) {
                                                $.magnificPopup.open({
                                                    items: {
                                                        src: this.href.replace(/^.*\/\/[^\/]+/, ''),
                                                        type: 'ajax'
                                                    },
                                                    enableEscapeKey: false,
                                                    closeOnBgClick: false,
                                                    callbacks: {
                                                        parseAjax: function (mfpResponse) {

                                                            mfpResponse.data = $(mfpResponse.data).removeClass('mfp-hide');
                                                            $(mfpResponse.data).find('span.title').text(modal_titulo);

                                                            $(mfpResponse.data).find('input.btn.ok').on('click', function() {
                                                                var agconta = getCookie('bra_iscli');
                                                                var seg_agconta = getCookie('bra_segcli');
                                                                var agcon = "";

                                                                var cAG = $(this).parents('form').children().find('input[name=AGN]').val();
                                                                var cCON = $(this).parents('form').children().find('input[name=CTA]').val();
                                                                var cDIG = $(this).parents('form').children().find('input[name=DIGCTA]').val();

                                                                if (cAG.length > 0 && cCON.length > 0 && cDIG.length > 0) {
                                                                    while (cAG.length < 4) {
                                                                        cAG = "0" + cAG;
                                                                    }

                                                                    while (cCON.length < 7) {
                                                                        cCON = "0" + cCON;
                                                                    }

                                                                    var now = new Date();
                                                                    var year = '0' + now.getFullYear();
                                                                    var month = '0' + (now.getMonth() + 1);
                                                                    var day = '0' + now.getDate();
                                                                    var hours = '0' + now.getHours();
                                                                    var minutes = '0' + now.getMinutes();
                                                                    var seconds = '0' + now.getSeconds();
                                                                    var ts = year.substr(year.length - 4, 4) + month.substr(month.length - 2, 2) + day.substr(day.length - 2, 2) + 'T' + hours.substr(hours.length - 2, 2) + minutes.substr(minutes.length - 2, 2) + seconds.substr(seconds.length - 2, 2);

                                                                    agcon = ts + "340989028374908D" + cAG + cCON + cDIG + "D982347509832745098324750923847";

                                                                    if(VerificaLoginHash(cAG,cCON,cDIG))   {
                                                                        setCookie('bra_iscli', agcon, 30);
                                                                        setCookie('Hash_MD5',"",30);
                                                                    }
                                                                    setCookie(cookie_ref + '_num', num_exibicoes, tmp_exibicao);

                                                                }
                                                            });
                                                            $(mfpResponse.data).find('input[name=ORIGEM]').val(transacional.origem);
                                                            $(mfpResponse.data).find('input[name=EXTRAPARAMS]').val(transacional.extraparams);
                                                            $(mfpResponse.data).find('input[name=CDSERVICO]').val(transacional.cdservico);

                                                        },
                                                        ajaxContentAdded: function() {
                                                            $(this.content).find('.formModalIB').attr('onsubmit', 'return ValidaLoginModalCampanha(\'' + form_ref + '\')');
                                                            $(this.content).find('.formModalIB').attr('id', form_ref);
                                                        }
                                                    }
                                                });

                                                e.preventDefault;
                                                return false;
                                            });
                                        }
                                    }
                                }
                            });
                        } else {
                            // chamada para campanhas animadas
                            abreCampanhaAnimada(segretorno, camp);

                        }
                    }
                }
            } else {
                if (existe && campanhaPersonalizada) {
                    // chamada para campanhas personalizadas, diferenciadas do fluxo padrao
                    abreCampanhaPersonalizada(segretorno, camp, dadosCampanhaPersonalizada, hash_global);
                }
            }
        }).fail(function(jqXHR, textStatus, errorThrown) {
            console.log(jqXHR, textStatus, errorThrown);
        });
    }
}
/* FIM - FUNCIONALIDADES CAMPANHAS */

/* INICIO - CONSULTA DE CONTAS CADASTRADAS EM CAMPANHAS */
function retornaConsultaBaseAGConta(agconta, camp) {
 var basePathURL = "";
 var url = "";
 var jsonText ="";

     if (location.href.indexOf("banco.bradesco") > -1) {
         basePathURL = "https://" + Global.TranslateAddress("wspf.banco.bradesco") + "/wsRemarketing/rmkt-search-agct_prioridade.aspx?i=";
     } else {
         basePathURL = Protocolo + '//' +  Global.TranslateAddress("wspf.banco.bradesco") + "/wsRemarketing/rmkt-search-agct_prioridade.aspx?i=";
     }

     if (camp == null || camp == "") {
        basePathURL = basePathURL + agconta
        url = basePathURL + agconta
    } else {
        basePathURL = basePathURL + agconta + "&camp=" + camp;
        url = basePathURL + agconta + "&camp=" + camp;
    }
    $.support.cors = true;
    var jqxhr = $.get(basePathURL, function(data, status) {
        VerificaPrioridade(data);
    }).fail(function() {
        console.log("wsRemarketing retornaConsultaBaseAGConta");
    });

    return '';
}
/* INICIO - CONSULTA DE CONTAS REAL TIME WEB PUSH */
function retornaConsultaBaseAGContaPush(agconta,IdPagina) {
    var basePathURL = "";
    var jsonText ="";

	if (location.href.indexOf("banco.bradesco") > -1) {
		basePathURL = "https://" + Global.TranslateAddress("wspf.banco.bradesco") + "/wsRemarketing/rmkt-search-agct_webpush.aspx?action=GetOffersIBWebPush&i=";
	} else {
		basePathURL = Protocolo + "//" + location.host.replace("7003", "7004") + "/wsRemarketing/rmkt-search-agct_webpush.aspx?action=GetOffersIBWebPush&i=";
	}
	basePathURL = basePathURL + agconta + IdPagina;

	$.getJSON(basePathURL, function (data) {
		setPushRealTime(data);
	});
}


function VerificaJornadaWebPush(){

 var Agconta = getCookie('bra_iscli');
 var IdPagina = "SEGUROAPPREMIAVEL";
	if (location.href.indexOf('classic/promocoes/seguro-ap-premiavel/index.shtm') > -1
		|| location.href.indexOf('exclusive/promocoes/seguro-ap-premiavel/index.shtm') > -1) {
		setCookie('PrimeiraJornada', 'true' , '1');
	}
	else {
		if (location.href.indexOf('html/classic') > -1 || location.href.indexOf('html/exclusive') >-1 ) {
			if (getCookie('PrimeiraJornada') == 'true') {
				if (Agconta.length > 0) {
					setCookie('PrimeiraJornada', '', '0');
					retornaConsultaBaseAGContaPush(Agconta, IdPagina)
				}
			}
		}
	}
}
function setPushRealTime(agconta_retornoWebPush) {

    var agCookies = getCookie('bra_iscli');
    var clienteAgencia = "";
    var seg_push = "";
    var camp_push = "";

    if (agCookies.length > 0) {
        agCookies = agCookies.split('D');
        clienteAgencia = agCookies[1].slice(0, 4);
    }
    if (agconta_retornoWebPush.length > 0) {
        camp_push = agconta_retornoWebPush[0].IdCampanha;
		camp_push = camp_push.split("=")[1];
        seg_push = agconta_retornoWebPush[0].Segmento;
    }
    // Codigo de campanha 671004 agencia e conta 028560071002
    // Codigo de campanha 670601 agencia e conta 000930108132
    // Codigo de campanha 670601 agencia e conta 028560580694

    // Clientes do chat de agencia digital

	try {
		var title = 'Seguro AP Premiável Bradesco';
		var icon = '/assets/classic/img/favicon.ico';
		var body = 'Garanta a proteção da sua família e ainda concorra a sorteios de R$ 200 mil todos os meses. CLIQUE AQUI E SIMULE AGORA!';
		var body2  = 'Caso não conseguir abrir a página acima, clique aqui';

		// granted: Usuário ja nos deu permissão para mostrar notificação no site atual;
		// denied: Usuário negou a permissão para mostrar notificação;
		// default: Usuário ainda não especificou se aprova notificação deste site.
		Notification.requestPermission().then(function(result) {
			console.log(result);
		});
		// testando se seu navegador suporta Web Notifications
		if (!window.Notification) {
			console.log("Seu navegador não suporta Web Notifications");
			//alert('Seu navegador não suporta Web Notifications')
			return;
		}

		if(Notification.permission === "granted")
		{
			var notification = new Notification(
				title, {
				icon: icon,
				body: body,
				body2: body2,
			});
			notification.onclick = function(){
				var basePathURL = "";
				var urlFinal = "/wsRemarketing/rmkt-search-agct_webpush.aspx?action=OfferAcceptedIBWebPush&i=" + getCookie('bra_iscli') + "&campaign=" + camp_push;
				if (location.href.indexOf("banco.bradesco") > -1) {
					basePathURL = location.protocol + '//' + Global.TranslateAddress("wspf.banco.bradesco") + urlFinal;
				} else {
					basePathURL = Protocolo + '//' + location.host.replace("7003", "7004") + urlFinal;
				}
				var jqxhr = $.get(basePathURL, function (data, status) {
					var retorno = data[0].IdCampanha;
				}).fail(function () {
					console.log("wsRemarketing SegundaJornada");
				});
				this.close();
				setTimeout(function () { window.open("/html/classic/promocoes/seguro-ap-premiavel/index.shtm?openModal", "_blank") }, 500);
			};
		} else if(Notification.permission === "default"){
			Notification.requestPermission(function() {
				var notification = new Notification(
					title, {
						icon: icon,
						body2: body2
					}
				);
				notification.onclick = function() {
					var basePathURL = "";
					var urlFinal = "/wsRemarketing/rmkt-search-agct_webpush.aspx?action=OfferAcceptedIBWebPush&i=" + getCookie('bra_iscli') + "&campaign=" + camp_push;
					if (location.href.indexOf("banco.bradesco") > -1) {
						basePathURL = location.protocol + '//' + Global.TranslateAddress("wspf.banco.bradesco") + urlFinal;
					} else {
						basePathURL = Protocolo + '//' + location.host.replace("7003", "7004") + urlFinal;
					}
					var jqxhr = $.get(basePathURL, function (data, status) {
						var retorno = data[0].IdCampanha;
					}).fail(function () {
						console.log("wsRemarketing SegundaJornada");
					});
					this.close();
					setTimeout(function () { window.open("/html/classic/promocoes/seguro-ap-premiavel/index.shtm?openModal", "_blank") }, 500);
				}
			});
		}
	} catch (err) {
		console.log('Erro Web Push : ' + err.message);
	}
}
/* FIM - CONSULTA DE CONTAS REAL TIME WEB PUSH */


/* INICIO - CONSULTA DE CONTAS CAMPANHAS COM PRIORIDADE */
function  VerificaPrioridade(data)
{
    var len = data.length;
    for (var i=0; i < len; i++){

      var prioridade     = data[i].Prioridade;
      var campanha = data[i].IdCampanha;
      var segmento = data[i].Segmento;
      var recoverCookie = getCookie('bra_camp_close_' + campanha);
      retornoglobal = prioridade +","+ segmento +","+ campanha +","

      if(recoverCookie == false  && campanha != 284 && campanha != 501 && campanha != 502 && campanha != 503 )
      {
        setCampaignMultiCamp(retornoglobal);
            return;
      }
      if(segmento.length > 0){
        setCookie('bra_segcli', segmento, 30);
      }

    }
    return;
}
function  mostrarModalPorID(cookie_ref) {
    console.log(arguments.callee.caller);
}

/* INICIO -SubHome empresas e negocios*/
function RetargetingComercioExterior(){
    if(location.href.indexOf('/html/pessoajuridica/solucoes-integradas/comercio-exterior/index.shtm') > -1 ) {

        var actualContext = '';
        actualContext = 'classic';
        img = "/assets/classic/img/retargeting/Intervencao_Empresas_Negocios.jpg";

            cookie_ref = 'Negocio_Emp';
            track_ref = parseInt(getCookie(cookie_ref + '_num')) || 0;

        if(track_ref <= 2)
            {

                $.magnificPopup.open({
                    items: {
                        src: '/assets/common/inc/modalRetargeting.shtm',
                        type: 'ajax'
                    },
                    enableEscapeKey: false,
                    closeOnBgClick: false,
                    showCloseBtn: false,
                    callbacks: {
                        parseAjax: function (mfpResponse) {
                            var style = 'background: url(' + img + ') center no-repeat;' + ' width: 700px; height: 480px;';
                            mfpResponse.data = $(mfpResponse.data).attr('style', style);

                            $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('style', 'position: absolute;  top: 59px;  left: 22px; width: 659px; height: 364px;');
                            $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('title', 'FECHAR');
                            $(mfpResponse.data).find('#lnk-rmkt-ver-depois').attr('href', '#');
                            $(mfpResponse.data).find('#lnk-rmkt-ver-depois').on('click', function() {
                            $.magnificPopup.close();
                                setCookie(cookie_ref + '_num',  (track_ref+1), 30);

                            });


                            $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('style', 'position: absolute;    top: 11px;    left: 672px;    width: 21px;    height: 27px;');
                            $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('title', 'FECHAR');
                            $(mfpResponse.data).find('#lnk-rmkt-fechar').html('X');
                            $(mfpResponse.data).find('#lnk-rmkt-fechar').attr('href', '#');
                            $(mfpResponse.data).find('#lnk-rmkt-fechar').on('click', function() {
                                $.magnificPopup.close();
                                setCookie(cookie_ref + '_num',  (track_ref+1) , 30);
                            });
                        },
                        ajaxContentAdded: function() {

                        }
                    }
                });
        } // Numero de exibicao
    }
}//FIM  SubHome
/* INICIO - Consulta segmentacao Virtual */
function logaSegmentacaoVirtual(){

    var agcontaglobal = getCookie('bra_iscli');
    var VerificaSegVirtual = getCookie('SegVirtual');
    var bra_segcli = getCookie('bra_segcli');

     if (agcontaglobal.length > 0){

            var basePathURL = "";
            var agconta_retornoglobal = "";
            var retornoglobalVirtual = "";
            var url = "";

            var SegVirtual = 'true';
            var SiteDomain = "banco.bradesco";
            var cookie = 'True';

            if(bra_segcli === 'Click Conta'){
                camp_local = 501;
            }else if(bra_segcli === 'CONTA UNIVERSITARIA'){
                camp_local = 502;
            }else if(bra_segcli === 'Poder Publico'){
                camp_local = 503;
            }else{
                camp_local = 284;
            }

            basePathURL = Protocolo + '//' +  Global.TranslateAddress("wspf.banco.bradesco") + "/wsRemarketing/rmkt-search-agct.aspx?i=";

            basePathURL = basePathURL + agcontaglobal + "&camp=" + camp_local + "&cookie=" + cookie;

            var jqxhr = $.get(basePathURL, function(data, status) {
                retornoglobalVirtual = (new XMLSerializer()).serializeToString(data).replace("<xml><retorno>", "").replace("</retorno></xml>", "");
                agconta_retornoglobal = retornoglobalVirtual.split(",");

                if (agconta_retornoglobal.length > 0) {
                    seg_global = agconta_retornoglobal[1];
                    camp_global = agconta_retornoglobal[2];

                    setCookie('SegVirtual', "", 1);

                    var Urlclassic = Protocolo + '//' +  Global.TranslateAddress(SiteDomain) + '/html/classic/index.shtm';
                    var Urlexclusive = Protocolo + '//' +  Global.TranslateAddress(SiteDomain) + '/html/exclusive/index.shtm';
                    var Urlprime = Protocolo + '//' +  Global.TranslateAddress(SiteDomain) + '/html/prime/index.shtm';
                    var Urlclickconta = Protocolo + '//' +  'www.clickconta.com.br/html/clickconta/index.shtm';
                    var UrlPoderpublico = Protocolo + '//' +  'www.bradescopoderpublico.com.br/html/poder_publico/pf/index.shtm';
                    var UrlUnivertaria = Protocolo + '//' +  'universitario.bradesco/html/cub/index.shtm';

                    var meuCookie = getCookie("SegVirtual_Outros");

                    if((camp_global == 501 || camp_global == 502 || camp_global == 503) &&  meuCookie == "")
                    {
                        setCookie('SegVirtual_Outros', true, 1);
                        meuCookie = true;
                    }
                    else
                        setCookie('SegVirtual_Outros', false, 1);


                    if(VerificaSegVirtual.length > 0)
                    {

                        if(seg_global === 'CLASSIC' || seg_global === 'classic')
                        {
                            if(location.href.indexOf('/html/classic/index.shtm') == -1 )
                            {
                                window.location.href =  Urlclassic;
                            }

                        } else if(seg_global === 'EXCLUSIVE' || seg_global === 'exclusive'  )
                        {
                            if(location.href.indexOf('/html/exclusive/index.shtm') == -1 )
                            {
                                window.location.href =  Urlexclusive;
                            }

                        }else if(seg_global === 'PRIME' || seg_global === 'prime'  )
                        {
                            if(location.href.indexOf('/html/prime/index.shtm') == -1 )
                            {
                                window.location.href =  Urlprime;
                            }
                        }

                    }else if((seg_global === 'CLICK CONTA' || seg_global === 'Click Conta') && meuCookie == true )
                    {
                     window.location.href =  Urlclickconta;

                 }else if((seg_global === 'PODER PUBLICO' || seg_global === 'Poder Publico') && meuCookie  == true )
                 {
                     window.location.href =  UrlPoderpublico;

                 }else if((seg_global === 'CONTA UNIVERSITARIA' || seg_global === 'conta universitaria') && meuCookie  == true)
                 {
                     window.location.href =  UrlUnivertaria;
                 }

             } else {
                var seg_global = '';
                var camp_global = '';
            }
        }).fail(function() {
            console.log("wsRemarketing logaSegmentacaoVirtual");
        });
     }

        campanha();
    }


function campanha(){

        // CAMPANHAS NAO ESTAO RESPONSIVAS, LOGO SO DEVEM SER CHAMADAS EM DESKTOP E TABLET
        if (agcontaglobal.length > 0 && $.ua.device.type != 'mobile') {
            retornaConsultaBaseAGConta(agcontaglobal, null);
            //retornaConsultaBaseAGContaPush(agcontaglobal);
        }

}
/* FIM - Consulta segmentacao virtual */

/* Funcao Onboarding Navegg*/
function setNaveggOndoarding(hash){

    nvg43243.setOnboard({
    prtid: 43243 ,
    prtusridf: hash
    })
}

function EnviaInformacaoSubHomeRT(agconta,escolha,campanha){

    var basePathURL = ''

    try {

            if(agconta.length > 0)
            {

               if (location.href.indexOf("banco.bradesco") > -1) {
                   basePathURL = "https://" + Global.TranslateAddress("wspf.banco.bradesco") + "/wsRemarketing/rmkt-search-agct_subhome-person-retorno.aspx?AgenciaConta=" + agconta + "&CampaignCode=" + campanha + "&Choice=" + escolha;
               } else {
                   basePathURL = Protocolo + '//' +  Global.TranslateAddress("wspf.banco.bradesco") + "/wsRemarketing/rmkt-search-agct_subhome-person-retorno.aspx?AgenciaConta=" + agconta + "&CampaignCode=" + campanha + "&Choice=" + escolha;
               }

               $.support.cors = true;
                var jqxhr = $.get(basePathURL, function(data, status) {
                var retorno = data;
                }).fail(function() {
                    console.log("wsRemarketing EnviaInformacaoSubHomeRT");
                });

                return "";

            }

        } catch (err) {
            console.log('Erro na Envio retorno Sub Home Real Time : ' + err.message);
        }

}

/* INICIO - Funcao subhome RT*/
function SetRetargetingSubHomeRT(){

    var basePathURL = "";
    var url = "";
    var jsonText ="";
    var retornoglobalRT = "";
    var agconta_retornoglobalRT = "";
    var agconta = getCookie('bra_iscli');
    var produto = "CREDITO";
    var camp_global = "";
    var seg_global = "";

    if (agconta.length > 0) {

        if (location.href.indexOf("banco.bradesco") > -1) {
            basePathURL = "https://" + Global.TranslateAddress("wspf.banco.bradesco") + "/wsRemarketing/rmkt-search-agct_subhome-person.aspx?i=";
        } else {
            basePathURL = Protocolo + '//' +  Global.TranslateAddress("wspf.banco.bradesco") + "/wsRemarketing/rmkt-search-agct_subhome-person.aspx?i=";
        }

       basePathURL = basePathURL + agconta + "&produto=" + produto;

        var jqxhr = $.get(basePathURL, function(data, status) {
                retornoglobalRT = (new XMLSerializer()).serializeToString(data).replace("<xml><retorno>", "").replace("</retorno></xml>", "");
                agconta_retornoglobalRT = retornoglobalRT.split(",");

                if (agconta_retornoglobalRT.length > 0) {

                    camp_global = agconta_retornoglobalRT[2];

                    if(agconta_retornoglobalRT[1] === 'Peace=1'){
                        seg_global = 'EXCLUSIVE';
                    } else if(agconta_retornoglobalRT[1] ==='Peace=2'){
                        seg_global = 'PRIME';
                    } else if(agconta_retornoglobalRT[1] ==='Peace=3'){
                        seg_global = 'CLASSIC';
                    }


                    if(camp_global == "261011" && location.href.indexOf('/html/classic/produtos-servicos/emprestimo-e-financiamento/index.shtm') > -1) {
                        $(".owl-item:first img:first").attr("src","/assets/classic/img/produtos-servicos/emprestimos-e-financiamentos/banners/banner_008.jpg");
                        $(".owl-item:first a").attr({
                            'href': '/assets/common/inc/modalIB.shtm',
                            'onclick': ""
                        });
                        $(".owl-item:first a").on('click', function(e) {
                            $.magnificPopup.open({
                                items: {
                                    src: this.href.replace(/^.*\/\/[^\/]+/, ''),
                                    type: 'ajax'
                                },
                                enableEscapeKey: false,
                                closeOnBgClick: false,
                                callbacks: {
                                    parseAjax: function (mfpResponse) {
                                        mfpResponse.data = $(mfpResponse.data).removeClass('mfp-hide');
                                        $(mfpResponse.data).find('input[name=CDSERVICO]').val('163');
                                        $(mfpResponse.data).find('span.title').text('Contrate Agora');
                                    }
                                }
                            });

                            e.preventDefault;
                            trackBannerAcoesGeral(seg_global, 'EmprÃƒÆ’Ã‚Â©stimos_Financiamentos_Home_Banner_1_CELULAR',camp_global,agconta);
                            trackBradesco(seg_global,'EmprÃƒÆ’Ã‚Â©stimos_Financiamentos_Home','Banner_1_CELULAR');
                            return false;
                        });
                    }else if(camp_global == "261012" && location.href.indexOf('/html/classic/produtos-servicos/emprestimo-e-financiamento/index.shtm') > -1)  {
                        $(".owl-item:first img:first").attr("src","/assets/classic/img/produtos-servicos/emprestimos-e-financiamentos/banners/banner_007.jpg");
                        $(".owl-item:first a").attr({
                            'href': '/assets/common/inc/modalIB.shtm',
                            'onclick': ""
                        });
                        $(".owl-item:first a").on('click', function(e) {
                            $.magnificPopup.open({
                                items: {
                                    src: this.href.replace(/^.*\/\/[^\/]+/, ''),
                                    type: 'ajax'
                                },
                                enableEscapeKey: false,
                                closeOnBgClick: false,
                                callbacks: {
                                    parseAjax: function (mfpResponse) {
                                        mfpResponse.data = $(mfpResponse.data).removeClass('mfp-hide');
                                        $(mfpResponse.data).find('input[name=CDSERVICO]').val('163');//
                                        $(mfpResponse.data).find('span.title').text('Contrate Agora');
                                    }
                                }
                            });

                            e.preventDefault;
                            trackBannerAcoesGeral(seg_global, 'EmprÃƒÆ’Ã‚Â©stimos_Financiamentos_Home_Banner_1_CELULAR',camp_global,agconta);
                            trackBradesco(seg_global,'EmprÃƒÆ’Ã‚Â©stimos_Financiamentos_Home','Banner_1_TV');
                            return false;
                        });
                    }
                }

        }).fail(function() {
            console.log("wsRemarketing SetRetargetingSubHomeRT");
        });

        return '';

    }// FIM consulta agencia e conta

}

//função sendo chamada pelo arquivo valida_agenciaconta;js
function AbandonoJornadaSAPP(ag,ct,dig){

        var agcontaglobal ="";
        var pagina = "SAPP";

     if (ag.length > 0){

        while (ag.length < 4) {
            ag = "0" + ag;
        }
        while (ct.length < 7) {
            ct = "0" + ct;
        }

        var basePathURL = "";
        var now = new Date();
        var year = '0' + now.getFullYear();
        var month = '0' + (now.getMonth() + 1);
        var day = '0' + now.getDate();
        var hours = '0' + now.getHours();
        var minutes = '0' + now.getMinutes();
        var seconds = '0' + now.getSeconds();
        var ts = year.substr(year.length - 4, 4) + month.substr(month.length - 2, 2) + day.substr(day.length - 2, 2) + 'T' + hours.substr(hours.length - 2, 2) + minutes.substr(minutes.length - 2, 2) + seconds.substr(seconds.length - 2, 2);

        agcontaglobal = ts + "340989028374908D" + ag + ct + dig + "D982347509832745098324750923847";

		basePathURL = Protocolo + '//' +  Global.TranslateAddress("wspf.banco.bradesco") + "/wsRemarketing/rmkt-search-agct_Jornada.aspx?i=";

		basePathURL = basePathURL + agcontaglobal + pagina;
		$.support.cors = true;

		if(location.href.indexOf("seguro-ap-premiavel") > -1){
			var jqxhr = $.get(basePathURL, function(data, status) {
				var retorno = data[0].IdCampanha;
			 }).fail(function() {
				console.log("wsRemarketing AbandonoJornadaSAPP");
			});
		}
    }
}

 /*FIM SetRetargetingSubHomeRT RT*/
$(document).ready(function () {

    $('body').on('click', 'input.btn-buscar', function (e) {
        e.preventDefault();
        if (this.form.textobusca.value != "") {
            logaNavegacaoComData("q=" + this.form.textobusca.value);

            envia(this.form.textobusca.value);
        }
    });


    /* INICIO -SubHome Personalizada*/
    if(location.href.indexOf('/html/classic/produtos-servicos/emprestimo-e-financiamento/index.shtm') > -1
        || location.href.indexOf('/html/exclusive/produtos-servicos/emprestimo-e-financiamento/index.shtm') > -1
        || location.href.indexOf('/html/prime/produtos-servicos/emprestimo-e-financiamento/index.shtmm') > -1) {

           //SetRetargetingSubHomeRT();
    }

     /* INICIO - Segmentar correntista*/
    if (location.href.indexOf('html/classic/index.shtm') > -1 || location.href.indexOf('html/exclusive/index.shtm') > -1|| location.href.indexOf('html/prime/index.shtm') > -1 ) {

        logaSegmentacaoVirtual();

    }

    /* FIM - Segmentar correntista*/
    logaNavegacaoComData('');
    logaNavegacaoServer();
    setHasMD5();
    //RetargetingComercioExterio();
    VerificaJornadaWebPush();

}); // $(document).ready(function ()

// Abre uma modal com layout diferenciado para as páginas abaixo
function NewmodalIB() {
    switch (location.pathname) {
        case '/html/classic/produtos-servicos/mais-produtos-servicos/atualizacao-de-endereco.shtm':
        case '/html/classic/produtos-servicos/mais-produtos-servicos/cadastro-de-e-mail.shtm':
        case '/html/classic/produtos-servicos/mais-produtos-servicos/cheques.shtm':
        case '/html/classic/produtos-servicos/mais-produtos-servicos/comprovantes-e-documentos.shtm':
        case '/html/classic/produtos-servicos/mais-produtos-servicos/debito-direto-autorizado-dda.shtm':
        case '/html/classic/produtos-servicos/mais-produtos-servicos/debito-automatico.shtm':
        case '/html/classic/produtos-servicos/mais-produtos-servicos/gerenciadores-financeiros.shtm':
        case '/html/classic/produtos-servicos/mais-produtos-servicos/infoemail-e-infocelular.shtm':
        case '/html/classic/produtos-servicos/mais-produtos-servicos/recarga-de-celular.shtm':
        case '/html/classic/produtos-servicos/mais-produtos-servicos/pagamentos.shtm':
        case '/html/classic/produtos-servicos/mais-produtos-servicos/portabilidade-de-salario.shtm':
        case '/html/classic/produtos-servicos/mais-produtos-servicos/transferencias-saques-e-depositos.shtm':
        case '/html/classic/produtos-servicos/mais-produtos-servicos/saldos-e-extratos.shtm':
        case '/html/classic/produtos-servicos/seguros/index.shtm':
                        
        case '/html/exclusive/produtos-servicos/mais-produtos-servicos/atualizacao-de-endereco.shtm':
        case '/html/exclusive/produtos-servicos/mais-produtos-servicos/cheques.shtm':
        case '/html/exclusive/produtos-servicos/mais-produtos-servicos/comprovantes-e-documentos.shtm':
        case '/html/exclusive/produtos-servicos/mais-produtos-servicos/debito-direto-autorizado-dda.shtm':
        case '/html/exclusive/produtos-servicos/mais-produtos-servicos/debito-automatico.shtm':
        case '/html/exclusive/produtos-servicos/mais-produtos-servicos/gerenciadores-financeiros.shtm':
        case '/html/exclusive/produtos-servicos/mais-produtos-servicos/infoemail-e-infocelular.shtm':
        case '/html/exclusive/produtos-servicos/mais-produtos-servicos/recarga-de-celular.shtm':
        case '/html/exclusive/produtos-servicos/mais-produtos-servicos/pagamentos.shtm':
        case '/html/exclusive/produtos-servicos/mais-produtos-servicos/portabilidade-de-salario.shtm':
        case '/html/exclusive/produtos-servicos/mais-produtos-servicos/transferencias-saques-e-depositos.shtm':
        case '/html/exclusive/produtos-servicos/mais-produtos-servicos/saldos-e-extratos.shtm': 
        case '/html/exclusive/produtos-servicos/seguros/index.shtm': 

        case '/html/prime/produtos-servicos/mais-produtos-servicos/atualizacao-de-endereco.shtm':
        case '/html/prime/produtos-servicos/mais-produtos-servicos/cadastro-de-e-mail.shtm':
        case '/html/prime/produtos-servicos/mais-produtos-servicos/cheques.shtm':
        case '/html/prime/produtos-servicos/mais-produtos-servicos/debito-automatico.shtm':
        case '/html/prime/produtos-servicos/mais-produtos-servicos/debito-direto-autorizado-dda.shtm':
        case '/html/prime/produtos-servicos/mais-produtos-servicos/gerenciadores-financeiros.shtm':
        case '/html/prime/produtos-servicos/mais-produtos-servicos/infoemail-e-infocelular.shtm':
        case '/html/prime/produtos-servicos/mais-produtos-servicos/pagamentos.shtm':
        case '/html/prime/produtos-servicos/mais-produtos-servicos/inss.shtm':
        case '/html/prime/produtos-servicos/mais-produtos-servicos/recarga-de-celular.shtm':
        case '/html/prime/produtos-servicos/mais-produtos-servicos/saldos-e-extratos.shtm':
        case '/html/prime/produtos-servicos/mais-produtos-servicos/portabilidade-de-salario.shtm':
        case '/html/prime/produtos-servicos/mais-produtos-servicos/transferencias-saques-e-depositos.shtm':
        case '/html/prime/produtos-servicos/seguros/index.shtm':

            $('.modalIB').attr('href','/assets/common/inc/modalIB_Conta.shtm');
            break;
        // default:
        //     $('.modalIB').attr('href','/assets/common/inc/modalIB.shtm');
    }
};
NewmodalIB();


