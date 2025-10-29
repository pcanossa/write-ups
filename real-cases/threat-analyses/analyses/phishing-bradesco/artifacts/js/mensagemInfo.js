jQuery(document).ready(function( $ ){
    var modalInfoMsg = document.createElement("a");
	modalInfoMsg.id = "lnkModalMsgInfo";
	modalInfoMsg.href = "/assets/common/inc/modalMsgInfo.shtm";
	modalInfoMsg.setAttribute('class', 'modalFree');
	modalInfoMsg.setAttribute('data-width', '600');
	modalInfoMsg.setAttribute('data-height', '200');
	$('footer').append(modalInfoMsg);
});

$(window).on('load', function() {
	var modalInfo = document.getElementById('lnkModalMsgInfo');
	
	// CLASSIC - CARTÕES
    if(location.href.indexOf('/html/classic/produtos-servicos/cartoes/') > -1){
		if(location.href.indexOf('/meu-cartao/prime-elo-nanquim/meu-cartao.shtm') > -1 ){	

			modalInfo.setAttribute('title', '');
			modalInfo.setAttribute('description', '<p>Em <b>01/02/2019</b> o Seguro Automático de Acidentes Pessoais do seu cartão será descontinuado, permanecendo válido até essa data.</p>');
			modalInfo.click();
		
		}
		
	// EXCLUSIVE - CARTÕES
	} else if(location.href.indexOf('/html/exclusive/produtos-servicos/cartoes/') > -1){
		if(location.href.indexOf('/conheca-os-cartoes/american-express-gold-credit.shtm') > -1 ||
		   location.href.indexOf('/conheca-os-cartoes/american-express-platinum-credit.shtm') > -1 ||
		   location.href.indexOf('/conheca-os-cartoes/cartao-bradesco-american-express-gold-credit.shtm') > -1 ||
		   location.href.indexOf('/conheca-os-cartoes/cartao-bradesco-exclusive-gold-american-express.shtm') > -1 ){
			   
			modalInfo.setAttribute('title', '');
			modalInfo.setAttribute('description', '<p>A partir de <b>15/11/2017</b>, para usar os seguros e assistências do seu Cartão American Express® em viagens no exterior, é necessário a emissão gratuita do bilhete de seguro e das cartas de viagem pelo site <a href="http://www.seguroviagembs.com.br/" target="_blank">www.seguroviagembs.com.br</a>.</p>');
			modalInfo.click();
			
		}else if(location.href.indexOf('/meu-cartao/bradesco-exclusive-visa-gold-credito/seguros-e-assistencias.shtm') > -1 ){
			
			modalInfo.setAttribute('title', '');
			modalInfo.setAttribute('description', '<p><b>A partir de 1º de fevereiro de 2019,</b> a Visa eliminará os benefícios de <b>Seguro de Acidentes Pessoais Durante a Viagem</b>. – Morte e Invalidez e de Morte ou Invalidez Permanente em Transporte Público Autorizado para todos os produtos elegíveis.</p>');
			modalInfo.click();
		
		}
	
	// PRIME - CARTÕES
	} else if(location.href.indexOf('/html/prime/produtos-servicos/cartoes/') > -1){
		}
});