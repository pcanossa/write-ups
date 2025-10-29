
jQuery(document).ready(function( $ ){

	// ----------------- Banner Abertura de Conta  -------------------------------
	
				/*
				if ( $.ua.device.type == 'mobile' ){
					if ( $.ua.os.name == 'iOS' ) {
						$('#lnkBanner03').attr('href','/html/classic/produtos-servicos/mais-produtos-servicos/pagamentos.shtm');
					} else if ( $.ua.os.name == 'Android' ) {
						$('#lnkBanner03').attr('href','/html/classic/produtos-servicos/mais-produtos-servicos/pagamentos.shtm');
					}
				} else {
	
				}
				*/
	
	// ----------------- Banner Abertura de Conta  -------------------------------
	
		var AreasRepetidas = ['imoveis', 'capitalizacao', 'investimentos', 'consorcios', 'cartoes', 'seguros', 'servicos', 'sobre', 'acessibilidade']
	
	// 	/* Manipula o JSON do Menu e monta o mesmo */
	// 	$.getJSON('js/main-menu.json', function(data){
	// 		function parseSubMenu(SubMenu) {
	// 			var ul = document.createElement('ul');
				
				
	// 			for(var i=0; i<SubMenu.length; i++ ) {
	// 				ul.appendChild(parseData(SubMenu[i]));
	// 			}
	// 			return ul;
	// 		}

			

	// 		function parseData(data) {
	// 			var li = document.createElement('li');
	// 			var link = document.createElement('a');
	// 			link.setAttribute('href', data.UrlArea);
	// 			link.setAttribute('tabindex', '45');
	// 			link.setAttribute('onclick', "trackBradesco('Portal Classic','Menu - Lateral','"+data.NomeArea+"');");

	// 			if (data.UrlArea == '/html/classic/produtos-servicos/emprestimo-e-financiamento/imoveis/credito-imobiliario-aquisicao-de-imoveis.shtm') {
	// 				link.setAttribute('onclick', "trackBradesco('Classic','Emprestimos Financimento Imoveis Home','Menu Lateral_credito-imobiliario-aquisicao-de-imoveis');");
	// 			} else if (data.UrlArea == '/html/classic/produtos-servicos/emprestimo-e-financiamento/imoveis/credito-imobiliario-construcao.shtm') {
	// 				link.setAttribute('onclick', "trackBradesco('Classic','Emprestimos Financimento Imoveis Home','Menu Lateral_credito-imobiliario-construcao');");
	// 			} else if (data.UrlArea == '/html/classic/produtos-servicos/emprestimo-e-financiamento/imoveis/credito-imobiliario-aquisicao-de-lote-urbano.shtm') {
	// 				link.setAttribute('onclick', "trackBradesco('Classic','Emprestimos Financimento Imoveis Home','Menu Lateral_credito-imobiliario-aquisicao-de-lote-urbano');");
	// 			} else if (data.UrlArea == '/html/classic/produtos-servicos/emprestimo-e-financiamento/imoveis/cdc-despesas-cartorarias.shtm') {
	// 				link.setAttribute('onclick', "trackBradesco('Classic','Emprestimos Financimento Imoveis Home','Menu Lateral_cdc-despesas-cartorarias');");
	// 			} else if (data.UrlArea == '/html/classic/produtos-servicos/emprestimo-e-financiamento/imoveis/cdc-material-de-construcao.shtm') {
	// 				link.setAttribute('onclick', "trackBradesco('Classic','Emprestimos Financimento Imoveis Home','Menu Lateral_cdc-material-de-construcao');");
	// 			} else if (data.UrlArea == '/html/classic/produtos-servicos/emprestimo-e-financiamento/imoveis/cdc-reforma-condominios-e-reuso-de-agua.shtm') {
	// 				link.setAttribute('onclick', "trackBradesco('Classic','Emprestimos Financimento Imoveis Home','Menu Lateral_cdc-reforma-condominios-e-reuso-de-agua');");
	// 			} else if (data.UrlArea == '/html/classic/produtos-servicos/emprestimo-e-financiamento/imoveis/cdc-aquecedores-solares.shtm') {
	// 				link.setAttribute('onclick', "trackBradesco('Classic','Emprestimos Financimento Imoveis Home','Menu Lateral_cdc-aquecedores-solares');");
	// 			} else if (data.UrlArea == '/html/classic/produtos-servicos/emprestimo-e-financiamento/imoveis/cdc-moveis-planejados.shtm') {
	// 				link.setAttribute('onclick', "trackBradesco('Classic','Emprestimos Financimento Imoveis Home','Menu Lateral_cdc-moveis-planejados');");
	// 			} else if (data.UrlArea == '/html/classic/produtos-servicos/emprestimo-e-financiamento/imoveis/fianca-de-aluguel.shtm') {
	// 				link.setAttribute('onclick', "trackBradesco('Classic','Emprestimos Financimento Imoveis Home','Menu Lateral_fianca-de-aluguel);");
	// 			} 
	// 			// Menu Lateral
	// 			else if (data.UrlArea == '/html/classic/produtos-servicos/index.shtm') {
	// 				link.setAttribute('onclick', "trackBradesco('Portal Classic - Home','Menu Lateral','Produtos e Serviços');");
	// 			}
	// 			else if (data.UrlArea == '/html/classic/promocoes/index.shtm') {
	// 				link.setAttribute('onclick', "trackBradesco('Portal Classic - Home','Menu - Produtos e serviços','Promoções e Campanhas');");
	// 			}
	// 			else if (data.UrlArea == '/html/classic/acessibilidade/index.shtm') {
	// 				link.setAttribute('onclick', "trackBradesco('Portal Classic - Home','Menu Lateral','Acessibilidade');");
	// 			}
	// 			else if (data.UrlArea == '/html/classic/sobre/index.shtm') {
	// 				link.setAttribute('onclick', "trackBradesco('Portal Classic - Home','Menu Lateral','Sobre o Bradesco');");
	// 			}
	// 			else if (data.UrlArea == '/html/classic/educacao-financeira/index.shtm') {
	// 				link.setAttribute('onclick', "trackBradesco('Portal Classic - Home','Menu Lateral','Educação Financeira');");
	// 			}
	// 			else if (data.UrlArea == '/html/classic/canais-digitais/index.shtm') {
	// 				link.setAttribute('onclick', "trackBradesco('Portal Classic - Home','Menu Lateral','Canais Digitais');");
	// 			}
	// 			else if (data.UrlArea == '/html/classic/atendimento/atendimento.shtm') {
	// 				link.setAttribute('onclick', "trackBradesco('Portal Classic - Home','Menu Lateral','Atendimento');");
	// 			}
	// 			// End Menu Lateral
	// 			else if (data.UrlArea == "https://banco.bradesco/soliciteseucartao?OrigeVda=913&PtoVda=001&TpoPto=3&Campa=913") {
	// 				link.setAttribute('onclick', "trackBradesco('Classic','Menu_Esq','Peca_seu_cartao');");
	// 			} else if (data.UrlArea == "/html/classic/produtos-servicos/cartoes/index.shtm") {
	// 				link.setAttribute('onclick', "trackBradesco('Classic','Menu_Esq','Cartoes);");
	// 			} else if (data.UrlArea == "/html/classic/produtos-servicos/cartoes/conheca-os-cartoes/index.shtm") {
	// 				link.setAttribute('onclick', "trackBradesco('Classic','Menu_Esq','Conheca_os_cartoes');");
	// 			} else if (data.UrlArea == "/html/classic/produtos-servicos/cartoes/meu-cartao/escolha-seu-cartao.shtm") {
	// 				link.setAttribute('onclick', "trackBradesco('Classic','Menu_Esq','Guia_digital');");
	// 			} else if (data.UrlArea == "/html/classic/produtos-servicos/cartoes/servicos/index.shtm") {
	// 				link.setAttribute('onclick', "trackBradesco('Classic','Menu_Esq','Servicos');");
	// 			} else if (data.UrlArea == "https://banco.bradesco/cartoes/ofertasebeneficios") {
	// 				link.setAttribute('onclick', "trackBradesco('Classic','Menu_Esq','Beneficios_ofertas');");
	// 			} else if (data.UrlArea == "/html/classic/produtos-servicos/cartoes/bradesco-cartoes/index.shtm") {
	// 				link.setAttribute('onclick', "trackBradesco('Classic','Menu_Esq','app_cartoes');");
	// 			} else if (data.UrlArea == "/html/classic/produtos-servicos/cartoes/pagamentos-digitais.shtm") {
	// 				link.setAttribute('onclick', "trackBradesco('Classic','Menu_Esq','Pagamentos_digitais');");
	// 			} else if (data.UrlArea == '/html/classic/produtos-servicos/renegociacao-de-dividas/index.shtm') {
	// 				if ($.ua.device.type != 'mobile')
	// 					link.setAttribute('onclick', "trackBradesco('Portal_Classic','Renegociação_de_dívidas','Menu_Renegociação_de_dívidas');");
	// 				else
	// 					link.setAttribute('onclick', "trackBradesco('Portal_Classic','Renegociação_de_dívidas','Menu_Renegociação_de_dívidas_Mobile');");
	// 			} else if (data.UrlArea == '/html/classic/produtos-servicos/renegociacao-de-dividas/canais-de-renegociacao.shtm') {
	// 				if ($.ua.device.type != 'mobile')
	// 					link.setAttribute('onclick', "trackBradesco('Portal_Classic','Renegociação_de_dívidas','Menu_Canais_de_renegociação');");
	// 				else
	// 					link.setAttribute('onclick', "trackBradesco('Portal_Classic','Renegociação_de_dívidas','Menu_Canais_de_renegociação_Mobile');");
	// 			} else if (data.UrlArea == '/html/classic/produtos-servicos/renegociacao-de-dividas/index.shtm#pre-aprovada') {
	// 				if ($.ua.device.type != 'mobile')
	// 					link.setAttribute('onclick', "trackBradesco('Portal_Classic','Renegociação_de_dívidas','Menu_Proposta_pré-aprovada');");
	// 				else
	// 					link.setAttribute('onclick', "trackBradesco('Portal_Classic','Renegociação_de_dívidas','Menu_Proposta_pré-aprovada_Mobile-aprovada');");
	// 			} else if (data.UrlArea == '/html/classic/produtos-servicos/renegociacao-de-dividas/faca-sua-proposta.shtm') {
	// 				if ($.ua.device.type != 'mobile')
	// 					link.setAttribute('onclick', "trackBradesco('Portal_Classic','Renegociação_de_dívidas','Menu_Faça_uma_proposta');");
	// 				else
	// 					link.setAttribute('onclick', "trackBradesco('Portal_Classic','Renegociação_de_dívidas','Menu_Faça_uma_proposta_Mobile');");
	// 			} else if (data.UrlArea == '/html/classic/produtos-servicos/renegociacao-de-dividas/index.shtm#assessoria') {
	// 				if ($.ua.device.type != 'mobile')
	// 					link.setAttribute('onclick', "trackBradesco('Portal_Classic','Renegociação_de_dívidas','Menu_Empresas_credenciadas');");
	// 				else
	// 					link.setAttribute('onclick', "trackBradesco('Portal_Classic','Renegociação_de_dívidas','Menu_Empresas_credenciadas_Mobile');");
	// 			}

	// 			li.className = data.ClassArea;
	// 			li.appendChild(link).innerHTML = data.NomeArea;
	// 			if (data.SubMenu) {
	// 				li.appendChild(parseSubMenu(data.SubMenu));
	// 			}
	// 			return li;
	// 		}
	
	// 		var menuMobile = (parseSubMenu(data));
	
	// 		// altera o menu para marcar areas repetidas antes de montar.
	// 		$(AreasRepetidas).each(function(indexArea) {
	// 			$(menuMobile).find('.' + AreasRepetidas[indexArea]).each(function(index) {
	// 				$(this).attr('class', AreasRepetidas[indexArea] + (index + 1))
	// 			});
	// 		});
	
	// 		var h2 = document.createElement('h2');
	// 		h2.appendChild(parseSubMenu(data));
	// 		document.getElementById('MainMenuMobile').appendChild(menuMobile);
	// 		document.getElementById('mainMenu').appendChild(h2);
	
	// 	}).done(function() {
	// 		var activePage = abreSubMenu();
	// 		var areaAtiva = 'none';
	// 		var codAreaAtiva = '';
	// 		var selected = $('#mainMenu .on');
	
	// 		// Verifica se pagina atual existe no menu.
	// 		var existeMenu = false;
	// 		var itensMenu = $('#mainMenu h2 ul li a');
	// 		$(itensMenu).each(function(index){
	// 			var pagina = $(this).attr('href').split('/');
	// 			pagina = pagina[pagina.length -1];
	
	// 			if(pagina == activePage + '.shtm'){
	// 				existeMenu = true;
	// 				return false;
	// 			}
	
	// 		});
	
	// 		// Verifica se pagina atual esta dentro das areas repetidas
	// 		if(selected.length  > 0 && $.inArray(activePage, AreasRepetidas) > -1 == true){
	// 			activePage = $(selected).attr('class').split(' ')[0] + $(selected).attr('class').split(' ')[1];
	// 		}
	
	// 		$('nav#mainMenu h2 ul li.active').each(function() {
	// 			areaAtiva = $(this).attr('class').split(' ')[0];
	// 			codAreaAtiva = $(this).attr('class').split(' ')[1];
	// 			// if para marcacao das areas repetidas
	// 			if(codAreaAtiva != 'active'){
	// 				areaAtiva = areaAtiva + codAreaAtiva;
	// 			}
	// 		});
	
	// 		$("#MainMenuMobile").mmenu({
	// 			offCanvas: {
	// 				pageSelector: "#wrapper",
	// 				position  : "right"
	// 				//zposition: "front"
	// 			}
	// 		},{
	// 			classNames: {
	// 				selected: areaAtiva,
	// 				fixedElements: {
	// 					fixed: "fixed"
	// 				}
	// 			}
	// 		});

	// 		// if para marcar no menu mobile se a pagina nao estiver no json do menu
	// 		if(existeMenu == false && $('#mainMenu .on').length > 0){
	// 			var activeClass = $('#mainMenu .on').attr('class').split(' ');
	// 			if (activeClass.length == 3 ){
	// 				activePage = activeClass[0] + activeClass[1];
	// 			}else{
	// 				activePage = activeClass[0];
	// 			}
	// 		}
	
	
	// 		$('ul.mm-listview li.'+ activePage +' a').addClass('on');
	// 		$('#topBar').removeClass('mm-slideout');
	// 		var api = $('#MainMenuMobile').data('mmenu');
	
	// 		// Muda o botão de abrir o menu mobile.
	// 		api.bind('opening', function () {
	// 			$('a.mobileMenu').addClass('close');
	// 		});
	// 		api.bind('closing', function () {
	// 			$('a.mobileMenu').removeClass('close');
	// 		});
	
	// 		// Muda o status do menu Hamburguer
	// 		$('.control_status').click(function(){
	// 			if (document.getElementById("control__nav").checked == false) {
	// 				document.getElementById("control__nav").checked = true;
	// 			} else {
	// 				document.getElementById("control__nav").checked = false;
	// 			}
	// 		});
	
	// 		  $('#mm-blocker').click(function(){
	// 			document.getElementById("control__nav").checked = false;
	// 		});
	
	// 		document.getElementById("mm-blocker").addEventListener("touchstart", myFunction);
	// 		function myFunction() {
	// 			document.getElementById("control__nav").checked = false;
	// 		}
	
	// 		// Insere o botão de Abra sua Conta no menu mobile.
	// 		$('<a href="/assets/common/inc/modalIB.shtm" class="botaoAbraConta modalIB" data-ncliente="nao" data-width="680" data-cdservico="001" data-title="Abra Sua Conta">Abra Sua Conta</a>').insertBefore('#MainMenuMobile div.mm-panels');
	
	// 		/*$('<form name="FormNaoCorrentista" id="FormNaoCorrentista" method="post" onsubmit="return ValidaFormNaoCorrentista(this);" action=" https://www.ib12.bradesco.com.br/ibpfnaocorrentistalogin/identificacao.jsf">' +
	// 			'&nbsp;&nbsp;&nbsp;&nbsp;' +
	// 			'<input name="CPF" type="text" id="CPF" title="Informe o número do CPF" tabindex="14" alt="cpf" onkeydown="formataCPF(this,event);" onfocus="textInitialCPF(this, false);" onblur="textInitialCPF(this, true);" placeholder="Cliente Não Correntista" maxlength="14" style="width: 170px;">' +
	// 			'&nbsp;' +
	// 			'<input type="submit" value="OK" title="Entrar" tabindex="15" onclick="trackBradesco("classic", "Cabecalho", "OKNaoCorrentista");">' +
	// 			'<a href="/html/classic/produtos-servicos/cartoes/cliente-nao-correntista.shtm" onclick="trackBradesco("Classic", "Cabecalho", "BotaoComoFunciona");" title="O acesso às informações do seu cartão mudou. Digite o CPF, clique em Primeiro acesso e faça seu recadastro.  Se você for um novo cliente, siga os mesmos passos." class="duvd"></a>' +
	// 			'<input type="hidden" name="IDENT" value="">' +
	// 			'<input type="hidden" name="ORIGEM" value="64">' +
	// 			'</form>').insertBefore('#MainMenuMobile div.mm-panels');*/
	
	// 		$(".nao-correntista").focusin(function() {
	// 			$("#CPF").val('');
	// 		});
	// 		$(".nao-correntista").focusout(function() {
	// 			$("#CPF").val('Não Correntista');
	// 		});
	// 		// Adiciona a função para abrir o chat no menu mobile.
	// 		$('#MainMenuMobile li.chat-internet-banking a').bind('click', function() {
	// 			chatIB();
	// 		});
	
	// 		// Calcula o altura do menu e ajusta a altura do conteúdo.
	// 		if ($.ua.device.type == undefined) {
	// 			var menuHeight = $('#mainMenu h2 ul').height();
	// 			$('section.mainContent').css('min-height',menuHeight + 145);
	// 		} else if ( $.ua.device.type == 'mobile' || $.ua.device.type == 'tablet'  ) {
	// 			$('section.mainContent').css('min-height','auto');
	// 		}
	
	// 		// Mostra o botÃ£o do canal do consorciado
	// 		if ($('#mainMenu > h2 > ul > li > ul > li.consorcios').hasClass('active')) {
	// 			$('body').addClass('consorciosSec');
	// 			$('div#topBar div.holder div.canal-consorciado').show();
	// 			$('<div class="canal-consorciado"><a href="#" onclick="ativaModalConsorcio();">Canal do Consorciado</a></div>').insertBefore('div.mm-panels');
	// 			$('#MainMenuMobile > div.mm-panels').css('top','96px');
	// 			if ( $.ua.device.type == 'tablet' ){
	// 				$('body.tablet div#topBar div.holder div.top-bar-center').hide();
	// 			}
	// 		} else {
	// 			$('div#topBar div.holder div.canal-consorciado').hide();
	// 		}
	
	
	
	// 		// Mostra o botão de acesso não correntista e troca para app de cartoes
	// 		if ($('#mainMenu > h2 > ul > li > ul > li.cartoes').hasClass('active')) {
	// 			$('body').addClass('cartoesSec');
	// 			if ( $.ua.device.type == 'mobile' ){
	
	// 				if($('div.holderMobile p')[0] != undefined) {
	// 						$('div.holderMobile p')[0].innerHTML = "<span>Gerencie seus cartões com o<br> Aplicativo Bradesco Cartões</span>";
	// 				}
	
	// 				if ( $.ua.os.name == 'Windows Phone' ){
	// 					$('div.holderMobile a.baixe').attr('href','https://www.microsoft.com/pt-br/store/apps/bradesco/9wzdncrfj2cs');
	// 				} else if( $.ua.os.name == 'iOS' ) {
	// 					$('div.holderMobile a.baixe').attr('href','https://itunes.apple.com/br/app/bradesco/id1073889634?mt=8');
	// 				} else if ( $.ua.os.name == 'Android' ) {
	// 					$('div.holderMobile a.baixe').attr('href','https://play.google.com/store/apps/details?id=br.com.bradesco.cartoes&hl=pt_BR');
	// 				}
	// 				$('div#topBar div.holder div.nao-correntista').hide();
	// 			} else {
	// 				$('div#topBar div.holder div.nao-correntista').show();
	
	// 				$.getScript("/assets/classic/js/produtos-servicos/cartoes/validaFormNaoCorrentista.js", function(){});
	// 				$.getScript("/assets/classic/js/produtos-servicos/cartoes/mascara.js", function(){});
	
	
	// 			$('<div class="nao-correntista"><a href="#" onclick="abreClienteNCorrentista(\'https://www.ib2.bradesco.com.br/cartoesbradesco/loginCartao.jsf\',\'750\',\'480\');">Cliente nÃ£o correntista</a></div>').insertBefore('div.mm-panels');
	// 			$('#MainMenuMobile > div.mm-panels').css('top','96px');
	
	// 			}
	// 			if ( $.ua.device.type == 'tablet' ){
	// 				$('div#topBar div.holder div.nao-correntista').show();
	
	// 				$.getScript("/assets/classic/js/produtos-servicos/cartoes/validaFormNaoCorrentista.js", function(){});
	// 				$.getScript("/assets/classic/js/produtos-servicos/cartoes/mascara.js", function(){});
	
	// 				$('body.tablet div#topBar div.holder div.top-bar-center').hide();
	// 			}
	// 		} else {
	// 			$('div#topBar div.holder div.nao-correntista').hide();
	// 		}
	
	// 		// Mostra o botão de acesso parceiros
	// 		if ($('nav#mainMenu > h2 > ul > li > ul > li > ul li.imoveis.2').hasClass('active')) {
	
	// 			$('body').addClass('imoveisSec');
	
	// 			$('.comboSegmentos .social-itens').show();
	// 			$('div#topBar div.holder div.btn-parceiros').show();
	// 			$('<div class="btn-parceiros"><a href="https://wspf.banco.bradesco/wsImoveis/AreaRestrita/" target="_blank">Acesso Parceiros</a></div>').insertBefore('div.mm-panels');
	// 			$('#MainMenuMobile > div.mm-panels').css('top','96px');
	
	// 			if ( $.ua.device.type == 'tablet' ){
	// 				$('body.tablet div#topBar div.holder div.top-bar-center').hide();
	// 			}
	
	// 		} else {
	// 			$('.comboSegmentos .social-itens').hide();
	// 			$('div#topBar div.holder div.btn-parceiros').hide();
	// 		}
	
	// 		// Adiciona o parametro do link de atendimento nos menus
	// 		if ( $('#mainMenu > ul > li > ul > li.capitalizacao').hasClass('active') ){
	// 			$('nav#mainMenu > ul > li.atendimento > a').attr('href','/html/classic/atendimento/atendimento.shtm?segmento=10287');
	// 		}
	// 		if ( $('#mainMenu > ul > li > ul > li.cartoes').hasClass('active') ){
	// 			$('nav#mainMenu > ul > li.atendimento > a').attr('href','/html/classic/atendimento/atendimento.shtm?segmento=4');
	// 		}
	// 		if ( $('#mainMenu > ul > li > ul > li.consorcios').hasClass('active') ){
	// 			$('nav#mainMenu > ul > li.atendimento > a').attr('href','/html/classic/atendimento/atendimento.shtm?segmento=8');
	// 		}
	// 		if ( $('#mainMenu > ul > li > ul > li.emprestimo-e-financiamento').hasClass('active') ){
	// 			$('nav#mainMenu > ul > li.atendimento > a').attr('href','/html/classic/atendimento/atendimento.shtm?segmento=14');
	// 		}
	// 		if ( $('#mainMenu > ul > li > ul > li.investimentos').hasClass('active') ){
	// 			$('nav#mainMenu > ul > li.atendimento > a').attr('href','/html/classic/atendimento/atendimento.shtm?segmento=15');
	// 		}
	// 		// Esconde listagem extensa de cartÃµes de Welcome Kit
	// 		if ($('nav#mainMenu li.meu-cartao').hasClass('active') && !$('nav#mainMenu li.meu-cartao').find('.active').is('li')) {
	// 		  $('nav#mainMenu li.meu-cartao ul').hide();
	// 		}
	
	// 		// Abrindo o item Agronegocio em nova aba
	// 		$('nav#mainMenu li.agronegocios a').attr('target','_blank');
	// 		// Abrindo o item Aposentados em nova aba
	// 		$('nav#mainMenu li.aposentados a').attr('target','_blank');
	// 		// Abrindo o item Universitários em nova aba
	// 		$('nav#mainMenu li.universitarios a').attr('target','_blank');
	
	// 		// Abrindo o item Agronegocio em nova aba
	// 		$('nav#mainMenu li.agronegocios a').attr('target','_blank');
	// 		// Abrindo o item Aposentados em nova aba
	// 		$('nav#mainMenu li.aposentados a').attr('target','_blank');
	// 		// Abrindo o item Universitários em nova aba
	// 		$('nav#mainMenu li.universitarios a').attr('target','_blank');
	
	// 		//Android Pay
	// 		$('nav#mainMenu li.android-pay a').attr('target','_blank');
	// 		// Samgung pay
	// 		$('nav#mainMenu li.samsumg-pay a').attr('target','_blank');
	
	// 		// Abrindo o item Premios em nova aba
	// 		$('nav#mainMenu li.premios a').attr('target','_blank');
	// 		// Abrindo o item Cursos Online em nova aba
	// 		$('nav#mainMenu li.cursos-online a').attr('target','_blank');
	
	// 		modalIB();
	
	// 	});
	// 	/* End: Manipula o JSON do Menu e monta o mesmo */
	
	// 	EscreveData();
	
	// 	// verificacao bug IE tablet
	// 	if($.ua.browser.name == "IE"  && $( document ).width() > 1024){
	// 		$.ua.device.type = undefined;
	// 	}
	// 	if($.ua.device.type != "mobile"){
	// 		var width = window.innerWidth || document.documentElement.clientWidth || document.body.clientWidth;
	// 		if (width < 640){
	// 			$.ua.device.type = "mobile";
	// 		}
	// 	}

	// 	$('section.mainContent').attr('tabindex','75');
	
	// 	$('input,textarea').placeholder();
	
	// 	var ms_ie = false;
	// 	var ua = window.navigator.userAgent;
	// 	var old_ie = ua.indexOf('MSIE ');
	// 	var new_ie = ua.indexOf('Trident/');
	
	// 	if ((old_ie > -1) || (new_ie > -1)) {
	// 		$("html").addClass("ie");
	// 	}
	
	// 	/* Tooltip */
	// 	var tmp1 = $.fn.tooltip.Constructor.prototype.show;
	// 	$.fn.tooltip.Constructor.prototype.show = function () {
	// 		tmp1.call(this);
	// 	}
	// 	var tmp2 = $.fn.tooltip.Constructor.prototype.hide;
	// 	$.fn.tooltip.Constructor.prototype.hide = function () {
	// 		tmp2.call(this);
	// 	}
	// 	$('[data-toggle="tooltip"]').tooltip({
	// 		html: true,
	// 		placement:'auto',
	// 		open: function(){
	// 			$('section.mainContent').css('overflow-x','initial');
	// 		},
	// 		close: function(){
	// 			$('section.mainContent').css('overflow-x','hidden');
	// 		},
	// 		viewport: {selector: '#wrapper', padding: 5}
	// 	});
	// 	/* End: Tooltip */
	
	// 	// Mobile Check
	// 	if ( $.ua.device.type == undefined ){
	
	// 		$('body').removeClass('mobile');
	// 		$('body').removeClass('tablet');
	
	// 		$('#topBar').show();
	
	// 	} else if( $.ua.device.type == 'mobile' ) {
	
	// 		$('body').addClass('mobile');
	
	// 		if(!sessionStorage.holderMobile) {
	// 			$('#wrapper').css({'padding-top':'135px'});
	// 			$('div.holderFixed').css({'top':'40px'});
	// 			$('.comboSegmentosHome').css({'top':'120px'});
	// 			$('#topBar').show();
	// 		} else {
	// 			$('#MainMenuMobile').css({'top':'0'});
	// 			$('#carousel-banner').css("cssText", "margin-top: 0 !important");		
	// 			$('.headerMobile').css("cssText", "top: 0 !important");
	// 			$('#MainMenuMobile').css("cssText", "top: 0px !important;");
	// 		}
	
	// 		if( $.ua.os.name == 'iOS' ) {
	// 			$('body').on('touchstart', '.tooltip', function(){
	// 				$(this).tooltip('hide');
	// 				$('.tip').css("color", "#1f1f1f");
	
	// 			});
	// 			$('body').on('touchstart', '.tip', function(){
	// 				$(this).tooltip('show');
	// 				$(this).css("color", "#75a7ec");
	// 			});
	// 		}else{
	// 			$('body').on('click', '.tooltip', function(){
	// 				$(this).tooltip('hide');
	// 			});
	// 		}
	
	// 	} else if ( $.ua.device.type == 'tablet' ) {
	
	// 		$('body').addClass('mobile tablet');
	
	// 		$('div.holderFooter').css('display','none');
	
	// 		if( $.ua.os.name == 'iOS' ) {
	// 			$('body').on('touchstart', '.tooltip', function(){
	// 				if($('.tooltip').hasClass('in')){
	// 					$(this).tooltip('hide');
	// 				}else{
	// 					$(this).tooltip('show');
	// 				}
	// 			});
	// 		}else{
	// 			$('body').on('click', '.tooltip', function(){
	// 				$(this).tooltip('hide');
	// 			});
	// 		}
	// 	}
	// 	// End: Mobile Check
	
	// 	// Alterando link da barra de aplicativos
	// 	if($('div.holderMobile p')[0] != undefined) {
	// 			$('div.holderMobile p')[0].innerHTML = "<span>Acesse ou abra sua conta<br> pelo Aplicativo Bradesco</span>";
	// 	}
	// 	if ( $.ua.os.name == 'Windows Phone' ){
	// 		$('div.holderMobile a.baixe').attr('href','https://www.bradescocelular.com.br/app_redirect/index.html?deeplink=app/listadeconta');
	// 	} else if( $.ua.os.name == 'iOS' ) {
	// 		$('div.holderMobile a.baixe').attr('href','https://www.bradescocelular.com.br/app_redirect/index.html?deeplink=app/listadeconta');
	// 	} else if ( $.ua.os.name == 'Android' ) {
	// 		$('div.holderMobile a.baixe').attr('href','https://www.bradescocelular.com.br/app_redirect/index.html?deeplink=app/listadeconta');
	// 	}
	// 	// End: Alterando link da barra de aplicativos
	
	// 	$(window).resize(function(){
	// 		closeMobileMenu();
	// 		$('.chosen-select-b1').trigger('chosen:close'); // Fecha o combo do footer no Window Resize
	// 		var wSize = $(window).width();
	// 		if ( wSize > 480 ){ // Se for maior que 480
	// 			$('h6.atendimento').removeClass('active'); // Coloca a seta do título na posição correta
	// 			$('div.holderFooter').css('display', 'block'); // Mostra o conteúdo do footer
	// 			//var magnificPopup = $.magnificPopup;
	// 			//if(typeof magnificPopup != 'undefined'){	 // Fecha o modal se estiver aberto
	// 			//	magnificPopup.close();
	// 			//}
	// 		}
	// 		if ( wSize < 640 ){
	// 			$('.chosen-drop').addClass('changeDir'); // Adiciona a classe que muda a direção em que abre o dropdown
	// 		}
	// 		if ( wSize >= 640 ){
	// 			$('.chosen-drop').removeClass('changeDir'); // Remove a classe que muda a direção em que abre o dropdown
	// 			$('header.headerMobile div.busca').removeClass('active'); // Remove a classe que muda a direção em que abre o dropdown
	// 		}
	// 		if ( wSize < 1024){
	// 			$('div.holderFooter').css('display', 'none'); // Esconde o conteúdo do footer
	// 			$('iframe').attr('scrolling','yes');
	// 			$('section.mainContent').css('min-height','auto');
	// 		}
	// 		if (wSize > 1024){
	// 			var menuHeight = $('#mainMenu').height();
	// 			$('section.mainContent').css('min-height',menuHeight);
	// 		}
	// 	});
	
	// 	// Limita a quantidade de caracteres no box de Educação Financeira
	// 	$(".educacao-financeira .box-normal .box-content-layouts h4").each(function (i) {
	// 		var text = $(this).text();
	// 		var len = text.length;
	// 		if (len > 76) {
	// 			var query = text.split(" ", 10);
	// 				query.push('...');
	// 				res = query.join(' ');
	// 			$(this).text(res);
	// 		}
	// 	});
	
	// 	$('body').on('click', 'ul.tabs li', function(e){ // Tabs
	// 		e.preventDefault();
	// 		var tabName = $(this).attr('rel');
	// 		if ( !$(this).hasClass('active') ){
	// 			$('ul.tabs li').removeClass('active');
	// 			$('div.tab').removeClass('active').hide();
	// 			$(this).addClass('active');
	// 			$('div.tab#'+ tabName +'').addClass('active');
	// 		}
	// 	});
	
	// 	$('body').on('click', 'div.tabsScroll ul li', function(e){ // Tab com scroll
	// 		e.preventDefault();
	// 		var tabName = $(this).attr('rel');
	// 		if ( !$(this).hasClass('active') ){
	// 			$('div.tabsScroll ul li').removeClass('active');
	// 			$('div.tab').removeClass('active').hide();
	// 			$(this).addClass('active');
	// 			$('div.tab#'+ tabName +'').addClass('active');
	// 		}
	// 	});
	
	// 	var magnificPopup = $.magnificPopup.instance;
	
	// 	$('.modalIframe').magnificPopup({
	
	
	// 		type: 'iframe',
	
	// 		iframe: {
	// 			markup: '<div class="mfp-iframe-scaler">'+
	// 					'<div class="mfp-close"></div>'+
	// 					'<div class="mfp-title">Some caption</div>'+
	// 					'<div class="scrollIframe">'+
	// 					'<iframe class="mfp-iframe" frameborder="0"></iframe>'+
	// 					'</div>'+
	// 					'</div>'
	// 		},
	// 		callbacks: {
	// 			markupParse: function(template, values, item) {
	// 				values.title = item.el.attr('title');
	// 			},
	// 			open: function() {
	// 				var modalWidth = $(magnificPopup.st.el).attr('data-width');
	// 				var modalHeight = $(magnificPopup.st.el).attr('data-height');
	// 				$('.mfp-content, .mfp-content iframe').css({
	// 					'max-width': modalWidth+'px',
	// 					'min-height': modalHeight+'px'
	// 				});
	// 			}
	// 		}
	// 	});
	
	// 	$('.modalURLExterna').magnificPopup({
	// 		type: 'ajax',
	// 		callbacks: {
	// 			parseAjax: function(mfpResponse) {
	// 				var data = $(mfpResponse.data).filter('#modalURLExterna').removeClass('mfp-hide');
	// 				var item = this.st;
	// 				data.find('a.btn-avancar').attr('href', item.el.data('url'));
	// 				mfpResponse.data = data;
	// 			}
	// 		}
	// 	});
	
	// 	function modalIB(){
	// 	var baixarApp = "";
	
	// 	$('.modalIB').magnificPopup({
	// 		type: 'ajax',
	// 		callbacks: {
	// 			parseAjax: function(mfpResponse) {
	// 				var data = $(mfpResponse.data).filter('#modalIB').removeClass('mfp-hide');
	// 				var item = this.st;
	// 				data.find('span.title').text(item.el.data('title'));
	// 				data.find('input#origemTrans').val(item.el.data('origem'));
	// 				data.find('input#campTrans').val(item.el.data('camp'));
	// 				data.find('input#extraParamsTrans').val(item.el.data('extraparams'));
	// 				data.find('input#shopinvestTrans').val(item.el.data('shopinvest'));
	// 				data.find('input#cdServico').val(item.el.data('cdservico'));
	// 				data.find('a.pdfmodal').attr('href',item.el.data('pdflink'));
	// 				data.find('form.formModalIB').attr('name',item.el.data('formmodalname'));
	// 				data.find('form.formModalIB').attr('onsubmit',item.el.data('onsubmit'));
	// 				data.find('form.formModalIB').attr('id',item.el.data('formmodalid'));
	// 				data.find('form.formModalIB input#AGN').attr("onblur", "ValidaNextAgencia(this.value);");
	// 				data.find('form.formModalIB input[type="submit"].ok').attr('onclick',item.el.data('trackok'));
	// 				data.find('form.formModalIB a.pdfmodal').attr('onclick',item.el.data('trackpdf'));
	// 				data.find('div.ncliente-modal a').attr('onclick',item.el.data('trackabraconta'));
	// 				if(item.el.data("trackbaixarapp") !== undefined){
	// 					baixarApp = 'onclick="' + item.el.data("trackbaixarapp") + '"';
	// 				}
	
	// 				var modalWidth = $(magnificPopup.st.el).attr('data-width');
	// 				$('.mfp-content').css({
	// 					'max-width': modalWidth+'px'
	// 				});
	// 				mfpResponse.data = data;
	// 			},
	// 			ajaxContentAdded: function(){
	// 				$(this.content).find('button.mfp-close').attr('onclick',$(magnificPopup.st.el).attr('data-trackfechar'));
	
	// 				if ( $.ua.device.type == 'mobile' ) {
	
	// 					var urlStore = '';
	// 						if ( $.ua.os.name == 'Windows Phone' ){
	// 							urlStore = 'https://www.microsoft.com/pt-br/store/apps/bradesco/9wzdncrfj2cs';
	// 						} else if( $.ua.os.name == 'iOS' ) {
	// 							urlStore = 'https://itunes.apple.com/br/app/bradesco/id336954985?mt=8';
	// 						} else if ( $.ua.os.name == 'Android' ) {
	// 							urlStore = 'https://play.google.com/store/apps/details?id=com.bradesco&hl=pt_BR';
	// 						}
	
	// 					var naoServico = $(magnificPopup.st.el).attr('data-servico');
	// 					var codservico = $(magnificPopup.st.el).attr('data-cdservico');
	// 					var codparam = $(magnificPopup.st.el).attr('data-extraparams');
	
	// 					if ( naoServico == undefined ){ var naoServico = 'nao'; }
	
	// 					if ( naoServico == 'sim' ){
	// 						$('div.modal section form').replaceWith('<div class="transacao-no-mobile"><span>Faça essa transação pelo Aplicativo Bradesco. Se não tem o app instalado, baixe agora!</span> <br> <br> <a href="' + urlStore +'" ' + baixarApp + '  class="btn btn-danger">Baixar App</></div>');
	// 					}
	// 					else if (codservico == '172' && codparam == 'CDPROD=495'){
	// 						$('div.modal section form').replaceWith('<div class="transacao-no-mobile"><span>Faça essa transação pelo Aplicativo Bradesco. Se não tem o app instalado, baixe agora!</span> <br> <br> <a href="' + urlStore + '" class="btn btn-danger">Baixar App</></div>');
	// 					}
	// 					else if (codservico == '001'){
	// 						$('div.modal section form').replaceWith('<div class="transacao-no-mobile"><span>Acesse o App Bradesco para abrir sua conta. Se ainda não tem instalado, baixe agora!</span> <br> <br> <a href="' + urlStore + '" class="btn btn-danger">Baixar App</></div>');
	// 					}
	// 					else {
	// 						$('div.modal section form').replaceWith('<div class="transacao-no-mobile"><span>Para realizar esta transação, acesse sua conta pelo computador ou tablet.</span></div>');
	// 					}
	
	// 				}
	// 				$('div.modal section div.ncliente').show();
	
	// 				if($(magnificPopup.st.el).attr('data-ncliente') == "nao"){
	// 					$('div.modal section div.ncliente').hide();
	// 				}
	// 			}
	// 		}
	// 	});
	// };
	
	
	$('.modalCartoesIB').magnificPopup({
			type: 'ajax',
			callbacks: {
				parseAjax: function(mfpResponse) {
					var data = $(mfpResponse.data).filter('#modalCartoesIB').removeClass('mfp-hide');
					var item = this.st;
					data.find('span.title').text(item.el.data('title'));
					data.find('input#origemTrans').val(item.el.data('origem'));
					data.find('input#campTrans').val(item.el.data('camp'));
					data.find('input#extraParamsTrans').val(item.el.data('extraparams'));
					data.find('input#shopinvestTrans').val(item.el.data('shopinvest'));
					data.find('input#cdServico').val(item.el.data('cdservico'));
					data.find('a.pdfmodal').attr('href',item.el.data('pdflink'));
					data.find('form.formModalCartoeslIB').attr('name',item.el.data('formmodalname'));
					data.find('form.formModalCartoeslIB').attr('onsubmit',item.el.data('onsubmit'));
					data.find('form.formModalCartoeslIB').attr('id',item.el.data('formmodalid'));
					data.find('form.formModalCartoeslIB input#AGN').attr("onblur", "ValidaNextAgencia(this.value);");
					// tracking
					data.find('form.formModalCartoeslIB input[type="submit"].ok').attr('onclick',item.el.data('trackok'));
					data.find('form.formModalCartoeslIB a.pdfmodal').attr('onclick',item.el.data('trackpdf'));
					data.find('div.ncliente-modal a').attr('onclick',item.el.data('trackabraconta'));
	
					var modalWidth = $(magnificPopup.st.el).attr('data-width');
					$('.mfp-content').css({
						'max-width': modalWidth+'px'
					});
					mfpResponse.data = data;
				},
				ajaxContentAdded: function(){
					$(this.content).find('button.mfp-close').attr('onclick',$(magnificPopup.st.el).attr('data-trackfechar'));
	
					if ( $.ua.device.type == 'mobile' ) {
	
						var urlStore = '';
							// if ( $.ua.os.name == 'Windows Phone' ){
							// 	urlStore = '';
							// } else
							if( $.ua.os.name == 'iOS' ) {
								urlStore = 'https://itunes.apple.com/br/app/bradesco/id336954985?mt=8';
							} else if ( $.ua.os.name == 'Android' ) {
								urlStore = 'https://play.google.com/store/apps/details?id=com.bradesco&hl=pt_BR';
							}
	
						var naoServico = $(magnificPopup.st.el).attr('data-servico');
						var codservico = $(magnificPopup.st.el).attr('data-cdservico');
						var codparam = $(magnificPopup.st.el).attr('data-extraparams');
	
						if ( naoServico == undefined ){ var naoServico = 'nao'; }
	
						if ( naoServico == 'sim' ){
							$('div.modal section form').replaceWith('<div class="transacao-no-mobile"><span>FaÃ§a essa transaÃ§Ã£o pelo Aplicativo Bradesco. Se nÃ£o tem o app instalado, baixe agora!</span> <br> <br> <a href="' + urlStore + '" class="btn btn-danger">Baixar App</></div>');
						}
						else if (codservico == '163' && codparam == 'CDPROD=495'){
							$('div.modal section form').replaceWith('<div class="transacao-no-mobile"><span>FaÃ§a essa transaÃ§Ã£o pelo Aplicativo Bradesco. Se nÃ£o tem o app instalado, baixe agora!</span> <br> <br> <a href="' + urlStore + '" class="btn btn-danger">Baixar App</></div>');
						}
						else {
							$('div.modal section form').replaceWith('<div class="transacao-no-mobile"><span>Para realizar esta transaÃ§Ã£o, acesse sua conta pelo computador ou tablet.</span></div>');
						}
	
					}
					$('div.modal section div.ncliente').show();
	
					if($(magnificPopup.st.el).attr('data-ncliente') == "nao"){
						$('div.modal section div.ncliente').hide();
					}
				}
			}
		});
	
	
		$('.modalFree').magnificPopup({
			fixedContentPos: true,
			type: 'ajax',
			callbacks: {
				parseAjax: function(mfpResponse) {
					var data = $(mfpResponse.data).filter('.modalFree');
					var item = this.st;
					data.find('span.title').text(item.el.attr('title'));
					data.find('div.descrition').text('').append(item.el.attr('description'));
					var modalWidth = $(magnificPopup.st.el).attr('data-width');
					var modalHeight = $(magnificPopup.st.el).attr('data-height');
					$('.mfp-content').css({
						'max-width': modalWidth+'px'
					});
					data.css({
						'min-height': modalHeight+'px'
					});
					mfpResponse.data = data;
				},
				open: function(){
					setTimeout(function(){
						$('[data-toggle="tooltip"]').tooltip({
							html: true,
							placement:'auto',
							viewport: {
								selector: 'section',
								padding: 5
							}
						});
					}, 100);
				},
				ajaxContentAdded: function(){
					if ( $.ua.device.type == 'mobile' ) {
	
						var naoServico = $(magnificPopup.st.el).attr('data-servico');
						if ( naoServico == undefined ){ var naoServico = 'nao'; }
	
						if ( naoServico == 'sim' ){
							var urlStore = '';
							if ( $.ua.os.name == 'Windows Phone' ){
								urlStore = 'https://www.microsoft.com/pt-br/store/apps/bradesco/9wzdncrfj2cs';
							} else if( $.ua.os.name == 'iOS' ) {
								urlStore = 'https://itunes.apple.com/br/app/bradesco/id336954985?mt=8';
							} else if ( $.ua.os.name == 'Android' ) {
								urlStore = 'https://play.google.com/store/apps/details?id=com.bradesco&hl=pt_BR';
							}
							$('div.modal section form').replaceWith('<div class="transacao-no-mobile"><span>Faça essa transação pelo Aplicativo Bradesco. Se não tem o app instalado, baixe agora!</span> <br> <br> <a href="' + urlStore + '" class="btn btn-danger">Baixar App</></div>');
						} else {
							if ($('#mainMenu > h2 > ul > li > ul > li.consorcios').hasClass('active')) {
								$('div.modal section form').replaceWith('<div class="transacao-no-mobile"><span>Para realizar esta transação, acesse sua conta pelo computador ou tablet.</span></div>');
							} else {
								$('div.modal section form').replaceWith('<div class="transacao-no-mobile">Para adquirir esse título, acesse sua conta pelo computador, tablet ou Aplicativo Bradesco.</div>');
							}
						}
	
					}
	
					$('div.modal section div.ncliente').show();
	
					if($(magnificPopup.st.el).attr('data-ncliente') == "nao"){
						$('div.modal section div.ncliente').hide();
					}
				}
			}
		});
	
		$('body').on('click', 'ul.accordion li a.lnkAcc', function(e){ // Accordion
			e.preventDefault();
			if ( $(this).hasClass('active') ){
				$(this).removeClass('active');
				$(this).parent().find('.description').stop(true, true).slideUp();
			} else {
				$(this).parent().parent().find('a.lnkAcc').removeClass('active');
				$(this).parent().parent().find('.description').stop(true, true).slideUp();
				$(this).addClass('active');
				$(this).parent().find('.description').stop(true, true).slideDown();
			}
		});
	
		$('#topBar a.fechar').on('click', function() { // Ao fechar a barrinha azul da versao mobile, ajusta a posição do header fixo
			$(this).parent().parent().hide();
			$('#wrapper').css({'padding-top':'95px'});
			$('div.holderFixed,#MainMenuMobile').css({'top':'0'});
			$('#carousel-banner').css("cssText", "margin-top: 0 !important");		
			$('.headerMobile').css("cssText", "top: 0 !important");
			// $('.control__nav').css("cssText", "top: -30px !important");
			$('#MainMenuMobile').css("cssText", "top: 0px !important;");
	
			
			sessionStorage.holderMobile = true;
		});
	
		$('div.como-usar, div.como-usar span').on('mouseenter focusin', function(){ // FunÃ§Ã£o que faz o menu "como usar" funcionar
			$(this).find('div.links').stop(true, true).fadeIn('fast');
			$('a[tabindex="13"]').focusout(function(){
				$('div.links').stop(true, true).fadeOut('fast');
			});
		}).on('mouseleave', function(){
			$(this).find('div.links').stop(true, true).fadeOut('fast');
		});
	
		$('ul.navSeg li.sub').on('mouseenter focusin', function() { // Função que faz funcionar o menu de segmentos
			$(this).addClass('active_arrow');
			$(this).find('div.navCnt').show().addClass('on');
			$('a[tabindex="24"], a[tabindex="38"], a[tabindex="41"]').focusout(function() {
				$('div.navCnt').stop(true, true).fadeOut('fast');
			});
		}).on('mouseleave', function(){
			$(this).find('div.navCnt').hide().removeClass('on');
			$(this).find('div.navCnt').hide().removeClass('on');
			$(this).removeClass('active_arrow');
		});
	
		$('div.navCnt div.maisperfis').on('mouseenter focusin', function(e) { // Faz o menu de mais perfis dentro do menu de segmentos funcionar
			e.preventDefault();
			$(this).parent().find('ul.sublvl').show();
		}).on('mouseleave', function(){
			$('ul.sublvl').hide();
		});
	
		$('ul.sublvl').on('mouseenter focusin', function(){ // Ativa submenu do menu de segmentos
			$(this).show();
		}).on('mouseleave', function(){
			$('ul.sublvl').hide();
		});
	
		$('.chosen-select-b1').chosen({ // Estiliza o combo do footer
			inherit_select_classes: true
		}).change(function(){
			var tipoCombo = $(this).attr('rel');
			var optUrl = $(this).val();
			var segmento = $(this).find(':selected').data('segmento');
			var area = $(this).find(':selected').data('area');
			var produto = $(this).find(':selected').data('produto');
			window.location.href = optUrl;
			trackBradesco(''+segmento+'',''+area+'',''+produto+'');
		});
	
		$('.chosen-select-b2').chosen({ // Estiliza o combo do footer
			inherit_select_classes: true
		}).change(function(){
			var tipoCombo = $(this).attr('rel');
			var optUrl = $(this).val();
			var segmento = $(this).find(':selected').data('segmento');
			var area = $(this).find(':selected').data('area');
			var produto = $(this).find(':selected').data('produto');
			window.open(optUrl);
			trackBradesco(''+segmento+'',''+area+'',''+produto+'');
		});
	
		$('h6.atendimento').on('click', function(){ // Abre o conteudo oculto do footer na versao mobile
			$('div.holderFooter').stop().slideToggle(function(){
				if ( $('h6.atendimento').hasClass('active') ){
					$('h6.atendimento').removeClass('active');
					$('.chosen-drop').addClass('changeDir');
				} else {
					$('h6.atendimento').addClass('active');
					$('.chosen-drop').removeClass('changeDir');
				}
			});
		});
	
		// A busca não tem mais essa animação
		// $('input[type="text"].input-autocomplete').on('focus',function(){ // Função que controla o tamanho do campo de busca no focu.
		//  $(this).animate({
		//      width: '300px'
		//  });
		// }).on('blur', function(){
		//  $(this).animate({
		//      width: '140px'
		//  });
		// });
	
		$('div.comboSegmentos h2').on('click', function() { // Função para abrir combo de segmento na versão mobile
			if ($('div.comboSegmentos').hasClass('active')) {
				$(this).parent().removeClass('active');
				$('div.comboSegmentos ul').css({
					'display': 'none',
					'visibility': 'hidden'
				});
			} else {
	
				$(this).parent().addClass('active').animate({
	
				}, 'fast', function(){
					$('div.comboSegmentos ul').css({
						'display':'block',
						'visibility':'visible'
					}).hide().fadeIn('fast');
				});
				$('div.comboSegmentos ul').css('display','block');
			}
		});
	
		$('.buscaMobile').on('click', function(e){
			e.preventDefault();
			if ( $('header.headerMobile div.busca').hasClass('active') ){
				$('header.headerMobile div.busca').removeClass('active');
				$('.headerMobile a').removeClass('active');
				$('.headerMobile .block_busca_open').removeClass('active');
				$(this).removeClass('close');
			} else {
				$('header.headerMobile div.busca').addClass('active');
				$('.headerMobile a').addClass('active');
				$('.headerMobile .block_busca_open').addClass('active');
				$(this).addClass('close');
			}
		});
	
		$(".busca-desk").focusin(function() {
			$(this).css("opacity", "1");
			$("#textobusca").removeAttr('placeholder');
		});
		$(".busca-desk").focusout(function() {
			$(this).css("opacity", "0.60");
			$("#textobusca").attr('placeholder', 'O que você procura?');
		});
	
		// Mobile
		$(".busca").focusin(function() {
			$(this).css("opacity", "1");
			$("#textobuscamobile").removeAttr('placeholder');
		});
		$(".busca").focusout(function() {
			$(this).css("opacity", "0.60");
			$("#textobuscamobile").attr('placeholder', 'O que você procura?');
		});
		/*
		Função para mandar pra slide especifico.
		var owl = $("#bannerCarousel").data('owlCarousel');
		owl.goTo(2);
		*/
	
		$("#bannerCarousel").owlCarousel({
			navigation : true, // Show next and prev buttons
			navigationText: ["&#9001","&#9002"],
			slideSpeed : 300,
			paginationSpeed : 400,
			singleItem:true,
			autoPlay: 5000,
			stopOnHover: true,
			paginationNumbers: true
		});
	
		$('a.modalVideoHTML5').on('click',function(e){
			e.preventDefault();
			var urlPoster = $(this).data('poster');
			var urlVideo = $(this).data('video');
			var autoPlay = $(this).data('autoplay');
			var vsrc = '';
			if ($.ua.browser.name == "IE" && $.ua.browser.version == "9.0") {
				vsrc = '<div class="holderVideo">'+
							'<object class="videoPlayerAdjust" type="application/x-shockwave-flash" data="/assets/common/swf/flashmediaelement.swf">'+
								'<param name="movie" value="/assets/common/swf/flashmediaelement.swf">'+
								'<param name="flashvars" value="controls=true&amp;autoplay=true&amp;file='+ urlVideo +'">'+
								'<param name="quality" value="high" />'+
								'<param name="wmode" value="transparent" />'+
							'</object>'+
						'</div>';
			} else {
				vsrc = '<div class="holderVideo">'+
							'<video width="100%" height="100%" poster="'+ urlPoster +'" controls="controls" preload="metadata">'+
								'<source type="video/mp4" src="'+ urlVideo +'" />'+
							'</video>'+
						'</div>';
			}
	
			$.magnificPopup.open({
				items: {
					src: vsrc,
					type: 'inline'
				},
				callbacks: {
					open: function() {
						var player = new MediaElementPlayer('video', {success: function(mediaElement, originalNode) {/* do things */}});
						if (autoPlay == "sim") {
							player.play();
						}
					}
				}
			});
		});
	
		$('a.modalVideoYoutube').magnificPopup({
			type: 'iframe',
			mainClass: 'mfp-youtube',
			removalDelay: 160,
			preloader: false,
			fixedContentPos: false
		});
	
		$('body').on("click", ".openPopup", function (c) {
		c.preventDefault();
		var f = this.getAttribute("href", 2),
			g = this.getAttribute("data-width") || 900,
			m = this.getAttribute("data-height") || 700,
			l = this.getAttribute("data-scrollbars") || "yes",
			k = this.getAttribute("data-toolbar") || "yes",
			e = this.getAttribute("data-resizable") || "yes",
			h = this.getAttribute("data-left") || (screen.width / 2) - g / 2,
			j = this.getAttribute("data-top") || (screen.height / 2) - m / 2,
			a = "height=" + m + ",width=" + g + ",toolbar=" + k + ",left=" + h + ",top=" + j + ",resizable=" + e + ",scrollbars=" + l,
			b;
		b = window.open(f, "popup", a);
		});
	
		$('body').on("change", "#central-atendimento", function () {// modal central de atendimento
			var caVal 	= $(this).val();
			var li 		= $("#central-atendimento option[value='"+caVal+"']").attr("data-ca");
			if(caVal == 'ca-all'){
				$("#ca-ul").find('li').show();
			}else{
				var arrayCA = new Array();
				arrayCA = li.split(",");
				$("#ca-ul").find('li').hide();
				$.each(arrayCA, function(item) {
					$('#'+arrayCA[item]).show();
				});
			}
		});
	
		$('body').on('click', 'ul#vant-ib li', function(){// vantagens canais digitais > internet bank
			var vantIB = $(this).attr('data-vant-ib');
			if ( !$(this).hasClass('active') ){
				$('ul#vant-ib li').removeClass('active');
				$('div.vant-ib-content').removeClass('active').hide();
				$(this).addClass('active');
				$('div.vant-ib-content#'+ vantIB).addClass('active').show();
			}
		});
	
		// Pulblicação dinamica para as páginas do Facebook e Twitter
		$(".ed-fn .twitter").click(function() {
			var twiter = "https://twitter.com/?status=https://www.bradesco.com.br" + location.pathname;
			$(this).attr("href", twiter)
		});
		$(".ed-fn .facebook").click(function() {
			var facebook = "https://www.facebook.com/sharer/sharer.php?u=https://www.bradesco.com.br" + location.pathname;
			$(this).attr("href", facebook)
		});
	
		// QA-Pacote 11 - habilitando target _blank programaticamente para carrosel com id carouselComoacessar
		$("#carouselComoacessar li").find("a").attr("target", "_blank");
	
		$('.produtos-navtabs > li').on('click', function(e) {
			var $el = $(this);
			var $wrapper = $('.produtos-navtabs-wrapper');
			if ($wrapper.scrollLeft() > $el.position().left || ($wrapper.scrollLeft() + $wrapper.width() < $el.width() + $el.position().left))
				$wrapper.scrollLeft($el.position().left);
		});
	
		// Chamada Weblibras
	
		// if ( $.ua.device.type == 'mobile' || $.ua.device.type == 'tablet'  ) {
	
		// 	$('#webLibrasCNT').hide();
	
		// } else {
	
		// 	// Carrega o CSS e JS do WebLibras
		// 	$('head').append('<link rel="stylesheet" type="text/css" href="css/wlStyle.css">');
		// 	$.getScript("/assets/common/js/wl-min.js");
	
		// 	// Funcao para Ativar o WebLibras
		// 	$('body').on('click', '#webLibrasCNT a', function(e){
		// 		e.preventDefault();
		// 		$('#startWlAuto').click();
		// 	});
	
		// }
	
	});
	
	function ativaModalConsorcio(){
		closeMobileMenu();
		$('#topBar div.canal-consorciado a').click();
	}
	
	function abreClienteNCorrentista(pagina, largura, altura){
		closeMobileMenu();
		w = screen.width;
		h = screen.height;
		meio_w = w/2;
		meio_h = h/2;
		altura2 = altura/2;
		largura2 = largura/2;
		meio1 = meio_h-altura2;
		meio2 = meio_w-largura2;
		window.open(pagina,'nao_correntista','height='+altura+',width='+largura + ',top='+meio1+',left='+meio2+',scrollbars=no,menubar=0,toolbar=0,statusbar=0,resizable=1');
		trackBradesco('Classic', 'Cartão - Cliente não conrretista', 'cliente_nao_correntista');
	}
	
	function EscreveData() {
		var mydate=new Date();
		var year=mydate.getYear();
		if (year < 1000) { year+=1900 }
		var day=mydate.getDay();
		var month=mydate.getMonth();
		var daym=mydate.getDate();
		if (daym<10) { daym="0"+daym }
		var dayarray=new Array("Domingo","Segunda-feira","Ter&ccedil;a-feira","Quarta-feira","Quinta-feira","Sexta-feira","S&aacute;bado");
		var montharray=new Array("janeiro","fevereiro","mar&ccedil;o","abril","maio","junho","julho","agosto","setembro","outubro","novembro","dezembro");
		$('span.txt-data').html(""+dayarray[day]+", "+daym+" de "+montharray[month]+" de "+year+"</b></font></small>");
	}
	
	function abreSubMenu() {
		// var url = location.href.split(/[?#]/)[0];
		// var breadcrumb = '';
		// var itemMenu = '';
		// url = url.split('/html/')[1];
		// url = url.split('/');
		// url.splice(0, 1);
	
		// $.each( url, function(idx, value) {
		// 	if ( value == '' ){
		// 		url[idx] = 'index.shtm';
		// 	}
		// });
	
		// if ( $('div.breadcrumb') ){
	
		// 	for (var i = 0; i < url.length; i++) {
		// 		if(url[i].indexOf('.') > -1) { url[i] = url[i].split('.')[0]; }
	
		// 		if (i == 0) {
		// 			itemMenu = '#mainMenu > h2 > ul > li.' + url[i];
	
		// 			$(itemMenu).addClass('active');
		// 			$(itemMenu + ' > ul').show();
	
		// 			breadcrumb += '<li class="seta">&rang;</li>';
	
		// 			breadcrumb += '<li><a href="' + $(itemMenu + ' > a').attr('href') + '" tabindex="-1">' + $(itemMenu + ' > a').text() + '</a></li>';
		// 		} else {
		// 			itemMenu += ' > ul > li.' + url[i];
	
		// 			if($(itemMenu).has('ul').length > 0) {
		// 				$(itemMenu).addClass('active');
		// 				$(itemMenu).siblings().hide();
		// 				$(itemMenu + ' > ul').show();
		// 			} else {
		// 				if($(itemMenu).length > 0) {
		// 					$(itemMenu).addClass('on');
		// 					$(itemMenu + ' > ul').show();
		// 				}
		// 			}
	
		// 			if (url[i].toLowerCase() != 'index') {
		// 				if($(itemMenu + ' > a').text() != "") {
		// 					breadcrumb += '<li class="seta">&rang;</li>';
		// 					breadcrumb += '<li><a href="' + $(itemMenu + ' > a').attr('href') + '" tabindex="-1">' + $(itemMenu + ' > a').text() + '</a></li>';
		// 				} else {
		// 					if (i == url.length-1) {
		// 						breadcrumb += '<li class="seta">&rang;</li>';
		// 						breadcrumb += '<li><a>' + $('.mainContent header h2').text() + '</a></li>';
		// 					}
		// 				}
		// 			}
		// 		}
		// 	}
	
		// 	$('.breadcrumb .links').append(breadcrumb);
	
		// 	if ( url[url.length - 1] == 'index' ){
		// 		var activePage = url[url.length - 2];
		// 	} else {
		// 		var activePage = url[url.length - 1];
		// 	}
	
		// 	return activePage;
		// }
	}
	
	function closeMobileMenu() { // Função para fechar o menu mobile
		var api = $('#MainMenuMobile').data('mmenu');
		if(typeof api != 'undefined'){
			api.close();
		}
	}
	
	function dvfoco(valor) {
		if (valor == 3) {
			$('#textobusca').focus();
		} else if (valor == 2) {
			$('#mainMenu h2 > ul > li:first > a').focus();
		} else if (valor == 1) {
			$('section.mainContent').focus();
			$("div#conteudo").focus();
			var scrollPos =  $("div#conteudo").offset().top;
			$(window).scrollTop(scrollPos - 80);		
		} else if (valor == 4) {
			$('div#footer').focus();
		} 
	}
	
	function envia(palavra) {
		if (palavra != '') {
			var urlpost = '/html/classic/resultado-busca/index.shtm?q=' + palavra + "&s=Classic";
			if (palavra != 'O que você procura?') {
				document.formbusca.action = urlpost;
				document.formbusca.submit();
			}
		}
	}
	
	bPagina.carregado(
		function () {
			bAutocomplete.criar('textobusca', 'lista', '', 'js/palavras.xml');
			bAutocomplete.incluiSelecaoItem('textobusca', execAutocomplete);
	
			bAutocompleteMobile.criar('textobuscamobile', 'listamobile', '', 'js/palavras.xml');
			bAutocompleteMobile.incluiSelecaoItem('textobuscamobile', execAutocomplete);
		}
	);
	
	function execAutocomplete(idElemento) {
		idElemento = idElemento || 'textobusca';
		envia(document.getElementById(idElemento).value);
	}
	
	function chatIB(){
		window.open("https://chats.bradesco/netcallcenter/chat5_internet/Cliente/frm_login.aspx?IdArea=1&Idioma=0&sel=HomePage","chat_ib","width=465,height=610,scrollbars=no,menubar=0,toolbar=0,statusbar=0,resizable=1");
		trackBradesco('Classic','Chat','Como_Usar_Chat_IB');
	}
	
	function chatSO(){
		window.open("https://xwc-bradesco.fnis.com.br/bradesco/pop_chat_bradesco_cartoes.html","Atendimento Online","width=600,height=400,scrollbars=no,menubar=0,toolbar=0,statusbar=0,resizable=1");
	}
	
	$(window).on('load', function(){
	
		$('#AGN').focus();
	
		// Tagueamento no menu lateral: Regularizacao de divida
		$("#mainMenu > ul > li.produtos-servicos > ul > li.mais-produtos-servicos > ul > li.regularizacao-de-divida > a, #MainMenuMobile li.regularizacao-de-divida a:last-child").attr("onclick", "trackBradesco('Classic','Menu Lado Esquerda','Mais Produtos e Servicos Regularizacao de Divida');");
	
		$("#mainMenu > ul > li.produtos-servicos > ul > li.mais-produtos-servicos > ul > li.regularizacao-de-divida > ul > li.canais-de-renegociacao > a, #MainMenuMobile li.canais-de-renegociacao a:last-child").attr("onclick", "trackBradesco('Classic','Menu Lado Esquerda','Mais Produtos e Servicos Regularizacao de Divida Canais de Renegociacao');");
	
		$("#mainMenu > ul > li.produtos-servicos > ul > li.mais-produtos-servicos > ul > li.regularizacao-de-divida > ul > li.proposta-pre-aprovada > a, #MainMenuMobile li.proposta-pre-aprovada a:last-child").attr("onclick", "trackBradesco('Classic','Menu Lado Esquerda','Mais Produtos e Servicos Regularizacao de Divida Proposta pre aprovada');");
	
		$("#mainMenu > ul > li.produtos-servicos > ul > li.mais-produtos-servicos > ul > li.regularizacao-de-divida > ul > li.faca-sua-proposta > a, #MainMenuMobile li.faca-sua-proposta a:last-child").attr("onclick", "trackBradesco('Classic','Menu Lado Esquerda','Mais Produtos e Servicos Regularizacao de Divida Faca sua proposta');");
	
		$("#mainMenu > ul > li.produtos-servicos > ul > li.mais-produtos-servicos > ul > li.regularizacao-de-divida > ul > li.assessorias-parceiras > a, #MainMenuMobile li.assessorias-parceiras a:last-child").attr("onclick", "trackBradesco('Classic','Menu Lado Esquerda','Mais Produtos e Servicos Regularizacao de Divida Assessorias Parceiras');");
	
		var tabName = window.location.hash.substr(1);
		if (tabName == 'tabCartoes'){
			if ( !$(this).hasClass('active') ){
				$('div.tabsScroll ul li').removeClass('active');
				$('div.tab').removeClass('active').hide();
				$(this).addClass('active');
				$('div.tabsScroll ul li#'+ tabName +'').addClass('active');
				$('div.tab#'+ tabName +'').addClass('active');
			}		
		}
	});
	
	function replaceSpecialChars(str){
		str = str.replace(/[Ã€ÃÃ‚ÃƒÃ„Ã…]/g,"A");
		str = str.replace(/[Ã Ã¡Ã¢Ã£Ã¤Ã¥]/g,"a");
		str = str.replace(/[ÃˆÃ‰ÃŠÃ‹]/g,"E");
		str = str.replace(/[Ã¨Ã©ÃªÃ«]/g,"e");
		str = str.replace(/[ÃŒÃÃŽÃ]/g,"I");
		str = str.replace(/[Ã¬Ã­Ã®Ã¯]/g,"i");
		str = str.replace(/[Ã’Ã“Ã”Ã•Ã–]/g,"O");
		str = str.replace(/[Ã²Ã³Ã´ÃµÃ¶]/g,"o");
		str = str.replace(/[Ã™ÃšÃ›Ãœ]/g,"U");
		str = str.replace(/[Ã¹ÃºÃ»Ã¼]/g,"u");
		str = str.replace(/[Ã‡]/g,"C");
		str = str.replace(/[Ã§]/g,"c");
		return str.replace(/[^ a-z0-9]/gi, "").trim();
	}
	
	function openPopupParceiros() {
		$('#topBar div.btn-parceiros a').click();
	}
	
	function openFooterTel() {
		$('#telefones_hidden').show(100);
		$('#setaFone').addClass('active_footer');
		$('#btnFone').attr('onclick', 'closeFooterTel()');
	}
	
	function closeFooterTel(){
		$('#telefones_hidden').hide(100);
		$('#setaFone').removeClass('active_footer');
		$('#btnFone').attr('onclick', 'openFooterTel()');
	}
	
	function openFooterInfo() {
		$('#informacoes_hidden').show(100);
		$('#setaInfo').addClass('active_footer');
		$('#btnInfo').attr('onclick', 'closeFooterInfo()');
	}
	
	function closeFooterInfo(){
		$('#informacoes_hidden').hide(100);
		$('#setaInfo').removeClass('active_footer');
		$('#btnInfo').attr('onclick', 'openFooterInfo()');
	}
// Abertura das abas do footer
	function InfoOpen() {
		$(".list__links").toggle();
		$(".item__info-uteis").toggleClass("active");
		$(".list__fones").css('display', 'none');
		$(".item__fones").removeClass("active");
		$(".item__bia").removeClass("active");
		$(".list__bia").css('display', 'none');
	}
	function InfoFone() {
		$(".list__fones").toggle();
		$(".item__fones").toggleClass("active");
		$(".list__links").css('display', 'none');
		$(".item__info-uteis").removeClass("active");
		$(".item__bia").removeClass("active");
		$(".list__bia").css('display', 'none');
	}
	function InfoBia() {
		$(".list__bia").toggle();
		$(".item__bia").toggleClass("active");
		$(".list__links").css('display', 'none');
		$(".item__info-uteis").removeClass("active");
		$(".item__fones").removeClass("active");
		$(".list__fones").css('display', 'none');
	}