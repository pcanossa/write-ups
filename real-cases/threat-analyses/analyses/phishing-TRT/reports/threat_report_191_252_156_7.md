# Relatório de Threat Intelligence – IP **191.252.156.7**

> **Fonte dos dados**: Shodan, IPInfo.io, VirusTotal, AbuseIPDB, WHOIS (registro.br), Scamalytics, MaxMind GeoLite2, DB‑IP, AlienVault OTX, URLScan.io.  
> **Timestamp da Análise**: 2026-01-15T12:27:26.470691  

---  

## 1. Resumo Executivo  
O endereço **191.252.156.7** pertence a um bloco IP alocado à Locaweb Serviços de Internet S/A (AS27715), operando em São Paulo, Brasil. Não foram encontradas evidências públicas de comportamento malicioso nos principais repositórios de inteligência (VirusTotal, AbuseIPDB, AlienVault OTX) e nenhum relatório de abuso foi registrado. O motor de busca do Shodan não retornou informações (404 Not Found), indicando que não há portas abertas ou serviços identificáveis a partir das sondagens realizadas. Os scores de risco de fontes externas (Scamalytics, FireHOL, Spamhaus) são “low/none”, reforçando a ausência de flag de comprometimento.  

## 2. Análise de Comportamento  
| Fonte | Indicador | Resultado |
|-------|-----------|-----------|
| **Shodan** | Busca por serviços/portas | Nenhum dado (404 Not Found) – o IP não respondeu a sondagens ou não possui serviços públicos identificados. |
| **VirusTotal** | Detecção de malware/abuso | 0 malicious, 0 suspicious, 93 undetected – nenhuma lista de bloqueio ou reputação negativa. |
| **AbuseIPDB** | Abuse Confidence Score | 0 – nenhum relatório de abuso. |
| **AlienVault OTX** | Pulses associados | Nenhum pulso encontrado. |
| **Scamalytics / FireHOL / Spamhaus** | Listas negras, proxy, datacenter | Não está listado como proxy, VPN ou em bloqueios conhecidos; risco “low”. |
| **WHOIS** | Dados de registro | Endereço alocado a Locaweb, uso típico de data‑center/VPS. |

**Conclusão comportamental:** Não há indícios de que o IP faça parte de botnets, servidores C2, scanners de portas ou outras infraestruturas de ataque. A ausência de serviços expostos (segundo Shodan) sugere que o host está provavelmente configurado como servidor interno ou VPS sem serviços públicos, o que reduz a superfície de ataque externa.

## 3. Superfície de Ataque  

### Portas abertas / Serviços
* **Nenhuma porta ou serviço foi identificado** pelos scanners públicos (Shodan).  
* Tentativa de conexão HTTP (porta 80) via `curl` resultou em “connection reset by peer”, reforçando a inexistência de serviço web público.

> **Observação:** Caso o IP esteja hospedando serviços internos (ex.: SSH, bancos de dados) sem exposição à internet, esses não são visíveis em bases públicas.

### Vulnerabilidades (CVEs) associadas
* Não há CVEs listados no relatório do Shodan ou em outras bases de vulnerabilidade para este endereço.  
* Sem serviços detectados, não há superfície de exploração conhecida.

## 4. Informações de Rede e Geográficas  

| Item | Detalhe |
|------|---------|
| **ASN** | **AS27715 – Locaweb Serviços de Internet S/A** |
| **ISP / Provedor** | **Locaweb Serviços de Internet S/A** |
| **País** | Brasil (BR) |
| **Região / Estado** | São Paulo |
| **Cidade** | São Paulo (coordenadas ‑23.6293, ‑46.6351) |
| **Latitude / Longitude** | -23.6293, -46.6351 |
| **Organização / Domínio** | `locaweb.com.br` – hostname `vpsw4940.publiccloud.com.br` |
| **Tipo de uso** | Data Center / Web Hosting / Transit (Conforme AbuseIPDB) |

## 5. Recomendações  

1. **Correlacionar logs internos** – Verificar logs de firewall, IDS/IPS e servidores de aplicação que tenham comunicações com 191.252.156.7 para confirmar se há tráfego legítimo ou inesperado.  
2. **Monitoramento contínuo** – Incluir o IP em soluções de *threat intel feed* (e.g., MISP, OpenCTI) para receber alertas caso ele seja inserido em listas negras futuramente.  
3. **Varredura interna** – Caso a sua organização possua ativos na mesma camada de rede (VLAN, datacenter), executar varredura interna (Nmap, Masscan) para confirmar se há portas abertas que não aparecem nas sondagens externas.  
4. **Revisar políticas de saída** – Garantir que conexões outbound para esse IP estejam sujeitas a inspeção, especialmente se houver tráfego de protocolos não‑HTTP (ex.: SSH, RDP, banco de dados).  
5. **Consultar fontes adicionais** – Realizar consultas periódicas em bases como GreyNoise, CIRCL·Passive DNS, e OSINT de malware (e.g., MalwareBazaar) para detectar possíveis novas associações.  
6. **Documentar e atualizar** – Manter registro de todas as análises e decisões, atualizando o status deste IP caso novas informações (e.g., relatórios de abuso) surjam.

---  

**Conclusão geral:** O endereço **191.252.156.7** não apresenta atualmente sinais de comprometimento ou atividade maliciosa em fontes públicas de inteligência. Sua exposição externa é mínima (sem portas abertas visíveis), reduzindo o risco imediato. Contudo, como se trata de um bloco de data‑center usado para VPS, recomenda‑se continuação do monitoramento e a verificação de tráfego interno para garantir que não seja utilizado como parte de infraestrutura interna de ataque ou como pivô para outras redes.