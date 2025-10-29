/* INICIO - Funções para criar, recuperar e deletar valores em cookies */
function setCookieIB(cname, cvalue, exdays) {
    var d = new Date();
    d.setTime(d.getTime() + (exdays * 24 * 60 * 60 * 1000));
    var expires = "expires=" + d.toGMTString();
    document.cookie = cname + "=" + cvalue + "; " + expires + "; path=/";
}

function getCookieIB(cname) {
    var name = cname + "=";
    var ca = document.cookie.split(';');

    for (var i = 0; i < ca.length; i++) {
        var c = ca[i].replace(" ", "");
        if (c.indexOf(name) == 0) return c.substring(name.length, c.length);
    }

    return "";
}

function deleteCookieIB(name) {
  document.cookie = name + '=; expires=Thu, 01 Jan 1970 00:00:01 GMT;';
}
/* FIM - Funções para criar, recuperar e deletar valores em cookies */

/* INICIO - Modal Navegador Exclusivo Bradesco */
function VerificaCookieModalNavegador() {

    if(location.href.indexOf('/html/pessoajuridica') > -1 ||
       location.href.indexOf('/html/corporate') > -1 ){

        var md = 3;//parseInt(getCookieIB('NavExcModal')) || 0;
        var NavegadorExclusivo = navigator.userAgent;

        // Useragent Navegador Exclusivo Bradesco em 10/2017
        // MAC: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:47.0) Gecko/20100101 Bradesco/1.0.1
        // 1.0.0 = NetExpress(1.0.0) Firefox/1.0.0 Mozilla/rv.29.0
        // 1.0.0.1 = NetExpress(1.0.0.1) Firefox/1.0.0.1 Mozilla/rv.29.0
        // 1.0.0.3 = NetExpress(1.0.0.3) Firefox/1.0.0.3 Mozilla/rv.29.0
        // 2.0.0 = NetExpress(2.0.0) Firefox/2.0.0 Mozilla/rv.29.0
        // 3.0.0 = NetExpress(3.0.0) Firefox/3.0.0 Mozilla/rv.29.0
        // 3.0.1 = NetExpress(3.0.1) Firefox/3.0.1 Mozilla/rv.29.0
        // 3.0.2 = NetExpress(3.0.2) Firefox/3.0.2 Mozilla/rv.29.0
        // 3.0.3 = NetExpress(3.0.3) Firefox/3.0.3 Mozilla/rv.29.0
        // 3.0.4 = NetExpress(3.0.4) Firefox/3.0.4 Mozilla/rv.29.0
        // 3.0.5 = NetExpress(3.0.5) Firefox/3.0.5 Mozilla/rv.29.0
        // 4.0.0 = NetExpress(4.0.0) Firefox/4.0.0 Mozilla/rv.29.0

		// Vai para Conta Colocar //
        if( $.ua.os.name == 'Mac OS' ||
           NavegadorExclusivo.indexOf('NetExpress(3.0.3)') > -1 ||
           NavegadorExclusivo.indexOf('NetExpress(3.0.5)') > -1 ||
           NavegadorExclusivo.indexOf('NetExpress(4.0.1)') > -1 ||
		   NavegadorExclusivo.indexOf('NetExpress(4.0.2)') > -1 ||
           NavegadorExclusivo.indexOf('Firefox/3.0.3') > -1 ||
           NavegadorExclusivo.indexOf('Firefox/3.0.5') > -1 ||
		   NavegadorExclusivo.indexOf('Firefox/4.0.1') > -1 ||
           NavegadorExclusivo.indexOf('Firefox/4.0.2') > -1 ) {
            $('.area-restrita.otherbrowser a.bt-md-nav-1').show();
            $('.area-restrita.otherbrowser a.bt-md-nav-2').hide();
            $('.area-restrita.otherbrowser a.bt-md-nav-3').hide();
            $('.area-restrita.otherbrowser a.bt-md-nav-4').hide();
        } else if (md > 2) {
            VerificaNavegadorExclusivoxOutros();
        }

        // Verifica se é o Chrome e mostra a interação do mesmo
        if ( $.ua.browser.name == 'Chrome' && $.ua.os.name == 'Windows' ){
            $('div.area-restrita.otherbrowser').hide();
            $('div.area-restrita.chrome').show();
        } else {
            $('div.area-restrita.otherbrowser').show();
            $('div.area-restrita.chrome').hide();
        }
    }
}
         //Elseif não vai para  conta//
function VerificaNavegadorExclusivoxOutros(){
    var NavegadorExclusivo = navigator.userAgent;
    if (NavegadorExclusivo.indexOf('Firefox/29.0') > -1 ||
        NavegadorExclusivo.indexOf('Bradesco/1.0.1') > -1 ||
        NavegadorExclusivo.indexOf('NetExpress(1.0' ) > -1 ||
        NavegadorExclusivo.indexOf('NetExpress(1.0.0)') > -1 ||
        NavegadorExclusivo.indexOf('NetExpress(1.0.1)') > -1 ||
        NavegadorExclusivo.indexOf('NetExpress(1.0.3)') > -1 ||
        NavegadorExclusivo.indexOf('NetExpress(1.0.0.1)') > -1 ||
        NavegadorExclusivo.indexOf('NetExpress(1.0.0.3)') > -1 ||
        NavegadorExclusivo.indexOf('NetExpress(2.0.0)') > -1 ||
        NavegadorExclusivo.indexOf('Firefox/2.0.0') > -1) {
        $('.area-restrita.otherbrowser a.bt-md-nav-1').hide();
        $('.area-restrita.otherbrowser a.bt-md-nav-2').hide();
        $('.area-restrita.otherbrowser a.bt-md-nav-3').hide();
        $('.area-restrita.otherbrowser a.bt-md-nav-4').show();
    } else if
       (NavegadorExclusivo.indexOf('NetExpress(3.0.0)') > -1 ||
        NavegadorExclusivo.indexOf('NetExpress(3.0.1)') > -1 ||
        NavegadorExclusivo.indexOf('NetExpress(3.0.2)') > -1 ||
        NavegadorExclusivo.indexOf('NetExpress(3.0.4)') > -1 ||
        NavegadorExclusivo.indexOf('NetExpress(4.0.0)') > -1 ||
        NavegadorExclusivo.indexOf('Firefox/3.0.0') > -1 ||
        NavegadorExclusivo.indexOf('Firefox/3.0.1') > -1 ||
        NavegadorExclusivo.indexOf('Firefox/3.0.2') > -1 ||
        NavegadorExclusivo.indexOf('Firefox/3.0.4') > -1 ||
        NavegadorExclusivo.indexOf('Firefox/4.0.0') > -1 ) {
        $('.area-restrita.otherbrowser a.bt-md-nav-1').hide();
        $('.area-restrita.otherbrowser a.bt-md-nav-2').hide();
        $('.area-restrita.otherbrowser a.bt-md-nav-3').show();
        $('.area-restrita.otherbrowser a.bt-md-nav-4').hide();
    } else {
        $('.area-restrita.otherbrowser a.bt-md-nav-1').hide();
        $('.area-restrita.otherbrowser a.bt-md-nav-2').show();
        $('.area-restrita.otherbrowser a.bt-md-nav-3').hide();
        $('.area-restrita.otherbrowser a.bt-md-nav-4').hide();
    }
}

function GravaCookieNavegadorSaibaMais(){
    setCookieIB('NavExcModal','',1);
    VerificaNavegadorExclusivoxOutros();
}

function GravaCookieNavegadorFechar(){
    setCookieIB('NavExcModal','',1);
    VerificaNavegadorExclusivoxOutros();
}

function GravaCookieModalNavegador(){
    var ExibicaoM = 1;
    ExibicaoM = parseInt(getCookieIB('NavExcModal')) || 0;
    setCookieIB('NavExcModal',(ExibicaoM+1),360);
}

function DirecionaLogin(){
    if(location.href.indexOf('/html/corporate') > -1){ //Corporate
        window.location.href ='https://www.ne12.bradesconetempresa.b.br/ibpjlogin/login.jsf?nscnn=2';
    } else {
        window.location.href ='https://www.ne12.bradesconetempresa.b.br/ibpjlogin/login.jsf';
    }
}

function trackModalNavegadorChrome(){
    setTimeout(function(){
        $("#modalChrome .mfp-close").attr("onclick", "trackBradesco('Intervencao','Chrome','Fechar');");
    }, 150);
}

function trackModalNavegadorExclusivoV1(){
    setTimeout(function(){
        $("#modalOtherBrowser .mfp-close").attr("onclick", "trackBradesco('Intervencao','Navegador Bradesco 1','Fechar');");
    }, 150);
}

function trackModalNavegador(){
    setTimeout(function(){
        $("#modalOtherBrowser .mfp-close").attr("onclick", "GravaCookieNavegadorFechar();DirecionaLogin();trackBradesco('Intervencao','Demais Navegadores','Fechar');");
    }, 150);
}

function trackModalNavegadorExclusivo(){
    setTimeout(function(){
        $("#modalOtherBrowser .mfp-close").attr("onclick", "GravaCookieNavegadorFechar();DirecionaLogin();trackBradesco('Intervencao','Navegador Bradesco','Fechar');");
    }, 150);
}
/* FIM - Modal Navegador Exclusivo Bradesco */

/* INICIO - CHAMADAS DAS FUNÇÕES */
/* OBS.: NÃO CRIAR outra chamada de $(document).ready() neste arquivo! */
$(document).ready(function () {
    // Modal Navegador Exclusivo Bradesco
    VerificaCookieModalNavegador();
});
/* FIM - CHAMADAS DAS FUNÇÕES */