/*
    global document: false
    setTimeout: false
    window: false
*/

function BAutocomplete() {
    var bCaixaTexto = {};           // caixa input
    var bLista = {};                // lista autocomplete
    var bPalavras = new Array();    // lista de palavras
    var bSeparador = {};            // default
    var bCaixaFuncao = {};          // fun��es iniciadas na sele��o do auto complete
    var add = false;
    this.criar = function(idCaixaTexto, idLista, palavras, caminhoXML) {
        var arrayPalavras = {};

        bCaixaTexto[idCaixaTexto] = document.getElementById(idCaixaTexto);
        if(!bCaixaTexto[idCaixaTexto]) {
            bCaixaTexto[idCaixaTexto] = document.createElement('button')
        }
        adicionaKeyUP(bCaixaTexto[idCaixaTexto]);
        bLista[idCaixaTexto] = document.getElementById(idLista);
        if(!bLista[idCaixaTexto]) {
            bLista[idCaixaTexto] = document.createElement('button');
        }
        bLista[idCaixaTexto].style.display = 'none';
        bLista[idCaixaTexto].style.width = '100%';

        // pego o evento keydown
        bLista[idCaixaTexto].onkeydown = function(e) { return AutoComplete_Key(document.getElementById(idCaixaTexto), e); }
        bCaixaTexto[idCaixaTexto].onkeydown = function(e) { return AutoComplete_KeyDown(this, e); }

        // se IE
        if (navigator.appName === "Microsoft Internet Explorer") {
            bLista[idCaixaTexto].style.left = parseInt(bCaixaTexto[idCaixaTexto].offsetLeft) + parseInt(bCaixaTexto[idCaixaTexto].parentNode.offsetLeft) + 'px';
            bLista[idCaixaTexto].style.top = parseInt(bCaixaTexto[idCaixaTexto].offsetTop) + parseInt(bCaixaTexto[idCaixaTexto].parentNode.offsetTop) + bCaixaTexto[idCaixaTexto].offsetHeight + 'px';
        } else {
            bLista[idCaixaTexto].style.left = parseInt(bCaixaTexto[idCaixaTexto].offsetLeft) + 'px';
            bLista[idCaixaTexto].style.top = parseInt(bCaixaTexto[idCaixaTexto].offsetTop) + bCaixaTexto[idCaixaTexto].offsetHeight + 'px';
        }

        // l� XML
        if (!(caminhoXML === null || caminhoXML === undefined)) {
            if (caminhoXML.length > 0) {
                arrayPalavras = leXML(caminhoXML);
            }
        }

        if (palavras.length > 0) {
            var arrayAux = palavras.split(',');
            var i = arrayPalavras[2] + 1;
            var ii;

            for (ii = 0; ii < arrayAux.length; ii++) {
                arrayPalavras[0][i] = arrayAux[ii];
                arrayPalavras[1][i] = arrayAux[ii];
                i++;
            }

            arrayPalavras[2] = i;
        }

        bPalavras[idCaixaTexto] = arrayPalavras;
        bSeparador[idCaixaTexto] = ',';
    };

    this.incluiSelecaoItem = function(idCaixaTexto, funcao) {
        bCaixaFuncao[idCaixaTexto] = funcao;
    };

    function AutoComplete_Key(obj, e) {
        if (bLista[obj.id].style.display === 'none')
            return;

        // Mozilla
        if (arguments[1] != null) {
            event = arguments[1];
        }

        var keyCode = event.keyCode;

        if (bLista[obj.id].style.display === 'none')
            return;

        // Mozilla
        if (arguments[1] != null) {
            event = arguments[1];
        }

        var keyCode = event.keyCode;

        switch (keyCode) {
            case 38: // Up
                if (bLista[obj.id].selectedIndex === 0) {
                    obj.focus();
                }
                break;

            case 9: // Tab
                bLista[obj.id].style.display = 'none';
                break;
        }
    }

    function AutoComplete_KeyDown(obj, e) {
        if (bLista[obj.id].style.display === 'none')
            return;

        // Mozilla
        if (arguments[1] != null) {
            event = arguments[1];
        }

        var keyCode = event.keyCode;

        if (bLista[obj.id].style.display === 'none')
            return;

        // Mozilla
        if (arguments[1] != null) {
            event = arguments[1];
        }

        var keyCode = event.keyCode;

        switch (keyCode) {
            case 38: // Up
                break;

            case 9: // Tab
                bLista[obj.id].style.display = 'none';
                break;

            case 40: // Down
                if (bLista[obj.id].tagName === 'DIV') {
                    return;
                }

                // Set next focus
                var el, l, k, e;
                k = 40;
                ec = e.target;

                if (k && !/textarea|select/i.test(ec.type) && !e.preventDefault()) {
                    for (l = k = (el = ec.form.elements).length; el[--k] != ec; );
                    while (!(ec = el[k = ++k * (k < l)]).type || ec.disabled);
                    ec.focus();
                }

                break;
        }
    }

    function leXML(caminho) {
        var palavra = {};
        var array1 = [];
        var array2 = [];
        var palavras, leXML, xmlhttp, i;

        try { //IE
            leXML = new ActiveXObject("Microsoft.XMLDOM");
            leXML.async = false;
            leXML.load(caminho);
        } catch (e) {
            try { // Firefox, Mozilla, Opera
                leXML = document.implementation.createDocument("", "", null);
                leXML.async = false;
                leXML.load(caminho);
            } catch (e) {
                try { //Chrome
                    xmlhttp = new window.XMLHttpRequest();
                    xmlhttp.open("GET", caminho, false);
                    xmlhttp.send(null);
                    leXML = xmlhttp.responseXML.documentElement;
                } catch (e) { }
            }
        } try {//le o xml
            palavras = leXML.getElementsByTagName("palavra");
        } catch (e) { return; }

        // le os node das palavras
        for (i = 0; i < palavras.length; i++) {
            array1[i] = palavras[i].childNodes[0].nodeValue;
            array2[i] = "" + i;
        }

        var palavra = new Array(array1, array2, i);

        return palavra;
    }

    //monta auto complete
    function adicionaKeyUP(elemento, caixaTexto, lista, palavras, separador) {
		try {
			if (window.addEventListener) {
				elemento.addEventListener('keyup', function(event) { exibirSelecao(event, elemento) }, false);
			} else if (window.attachEvent) {
				elemento.attachEvent('onkeyup', function(event) { exibirSelecao(event, elemento) });
			}
		} catch (e) { }
    }

    //filtra as palavras e mostra o auto complete
    function exibirSelecao(event, elemento) {
        var keynum;
        var keychar;
        var palavra = elemento.value;
        var qtd = 0;

		if (palavra.length > 2) {
			if (window.event) {
				keynum = event.keyCode;
			} else if (event.which) {
				keynum = event.which;
			};

			var palavras = new Array(1000);
			palavras = bPalavras[elemento.id][0];
			var ids = bPalavras[elemento.id][1];

			if (bLista[elemento.id].tagName == 'DIV') {
				var divs = bLista[elemento.id].getElementsByTagName('div');

				while (divs.length !== 0) {
					bLista[elemento.id].removeChild(divs[0]);
				}
			}
			else {
				while (bLista[elemento.id].length !== 0) {
					bLista[elemento.id].remove(bLista[elemento.id].length - 1);
				}

				bLista[elemento.id].size = 1;
			}

			if (palavra !== '') {
			    var existe = false;

				for (var contador = 0; contador < bPalavras[elemento.id][2]; contador++) {
					var testePalavra = palavras[contador].substring(0, palavra.length);

					if (testePalavra.indexOf(palavra) == 0) {
						qtd++;
						if (bLista[elemento.id].tagName == 'DIV') {
							var palavraEl = document.createElement('div');
							var palavraText = document.createTextNode(palavras[contador]);

							palavraEl.appendChild(palavraText);
							adicionaClick(palavraEl, bCaixaTexto[elemento.id], bLista[elemento.id]);
							palavraEl.style.width = '100%';
							bLista[elemento.id].appendChild(palavraEl);
							existe = true;
						} else {
							if (!add) {
								adicionaDBLClick(bLista[elemento.id], bCaixaTexto[elemento.id]);
								adicionaClickSel(bLista[elemento.id], bCaixaTexto[elemento.id]);
								adicionaENTER(bLista[elemento.id], bCaixaTexto[elemento.id]);
								add = true;
							}

							bLista[elemento.id].size = bLista[elemento.id].size + 1;
							var palavraEl = document.createElement('option');
							palavraEl.setAttribute('id', ids[contador]);
							palavraEl.text = palavras[contador];

							try {
								bLista[elemento.id].add(palavraEl, null);
							} catch (ex) {
								bLista[elemento.id].add(palavraEl);
							}

							existe = true;
						}
					}
				}

				if (existe) {
					bLista[elemento.id].style.display = 'block';
				} else {
					bLista[elemento.id].style.display = 'none';
				}
			} else {
				bLista[elemento.id].style.display = 'none';
			}
		} else {
			bLista[elemento.id].style.display = 'none';
		}
    }

    function adicionaClick(elemento, caixaTexto, lista) {
        if (window.addEventListener) {
            elemento.addEventListener('click', function() { selecionar(elemento, caixaTexto, lista) }, false);
        } else if (window.attachEvent) {
            elemento.attachEvent('onclick', function() { selecionar(elemento, caixaTexto, lista) });
        }
    }

    function adicionaDBLClick(elemento, caixaTexto, lista) {
        if (window.addEventListener) {
            elemento.addEventListener('click', function() { selecionarListBoxNoclose(caixaTexto, elemento) }, false);
        } else if (window.attachEvent) {
            elemento.attachEvent('onclick', function() { selecionarListBoxNoclose(caixaTexto, elemento) });
        }
    }

    function adicionaClickSel(elemento, caixaTexto, lista) {
        if (window.addEventListener) {
            elemento.addEventListener('dblclick', function() { selecionarListBox(caixaTexto, elemento) }, false);
        } else if (window.attachEvent) {
            elemento.attachEvent('ondblclick', function() { selecionarListBox(caixaTexto, elemento) });
        }
    }

    function adicionaENTER(elemento, caixaTexto, lista) {
        if (window.addEventListener) {
            elemento.addEventListener('keypress', function(event) { selecionarENTER(event, elemento, caixaTexto) }, false);
        } else if (window.attachEvent) {
            elemento.attachEvent('onkeypress', function(event) { selecionarENTER(event, elemento, caixaTexto) });
        }
    }

    function selecionarENTER(event, elemento, caixaTexto) {
        var keynum;

        if (window.event) {
            keynum = event.keyCode;
        } else if (event.which) {
            keynum = event.which;
        }

        if (keynum === 13) {
            selecionarListBox(caixaTexto, elemento);
        }
    }

    function selecionarListBox(caixaTexto, lista) {
        caixaTexto.value = lista.options[lista.selectedIndex].text;
        lista.style.display = 'none';

        executaFuncao(caixaTexto.id);
    }

    function selecionarListBoxNoclose(caixaTexto, lista) {
        caixaTexto.value = lista.options[lista.selectedIndex].text;

        executaFuncao(caixaTexto.id);
    }

    function selecionar(elemento, caixaTexto, lista) {
        caixaTexto.value = elemento.childNodes[0].nodeValue;
        lista.style.display = 'none';

        executaFuncao(caixaTexto.id);
    }

    function executaFuncao(id) {
        if (typeof bCaixaFuncao[id] == "function") {
            switch (id) {
                case 'textobusca':
                case 'textobuscamobile':
                    bCaixaFuncao[id](id);
                    break;

                default:
                    bCaixaFuncao[id]();;
            }
        }
    }
}

var bAutocomplete = new BAutocomplete();
var bAutocompleteMobile = new BAutocomplete();