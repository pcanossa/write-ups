# Relatório de Threat Intelligence – IP **172.67.156.69**

> **Fonte dos dados**: Shodan, IPInfo.io, URLScan.io, VirusTotal, AbuseIPDB, WHOIS (ARIN), AlienVault OTX, cabeçalhos HTTP (cURL), Scamalytics.  
> **Timestamp da Análise**: 2026-01-14T12:35:38.520729.

---

## 1. Resumo Executivo
O endereço **172.67.156.69** pertence à rede de distribuição da **Cloudflare (AS13335)**, com data center em **San Francisco, CA, EUA**. Não há relatos de abuso direto (Abuse Confidence Score 0) e a pontuação de risco em fontes externas (Scamalytics) é **baixa**. O IP está exposto como um **CDN** que hospeda diversos domínios, incluindo *intuitivelivinghub.com*, *holmes456.acessoportalatendimento.app*, e *ozfishingstore.com*. Portas abertas típicas de servidores web (80/443) e várias portas de administração (2052‑2096, 8080‑8443, 8880) foram observadas no Shodan. Embora os serviços pareçam legítimos (Cloudflare reverse‑proxy), o IP tem sido utilizado para distribuir **APK** e **EXE** potencialmente maliciosos (ex.: variantes de AgentTesla, FormBook, MSIL/Kryptik, Mokes).  

## 2. Análise de Comportamento
| Fonte | Evidência | Interpretação |
|-------|-----------|---------------|
| **Shodan** | Portas 80, 443, 2052‑2096, 8080‑8443, 8880; serviço “Cloudflare” | Servidor de CDN/reverse‑proxy. As portas de administração (2052‑2096) são frequentemente usadas por painéis de controle (cPanel, Plesk) e podem indicar serviços expostos ou testes de configuração. |
| **URLScan.io** | Diversos domínios apontando ao IP (e.g., *intuitivelivinghub.com*, *holmes456.acessoportalatendimento.app*, *ozfishingstore.com*) | O IP serve como ponto de entrega de conteúdo web para múltiplos sites; alguns desses sites podem ser usados para phishing ou distribuição de malware. |
| **VirusTotal – Arquivos associados** | - APKs: *Sonar FM*, *Intuitivelivinghub* (não detectados como maliciosos, mas contêm SDKs de anúncios e permissões de internet). <br>- EXE: *CitizenMP.exe* (CrimeZ), *Err.exe* (AgentTesla/Variadic), *SymAddressKi.exe* (MSIL/Kryptik), *michv‑v4.0‑10.apk* (FormBook), *e6c54… .virus* (Mokes), *SymAddressKi.exe* (AgentTesla) | Vários binários vinculados ao IP apresentam comportamento de **trojan, downloader, key‑logger e informações de C2**. A presença de agentes como **AgentTesla**, **Formbook**, **Mokes**, **Kryptik** indica que o IP está sendo usado como *C2* ou *distribuidor* de cargas maliciosas. |
| **AbuseIPDB** | Abuse Confidence Score = 0, 1 reporte (não classificado como abuso) | O IP ainda não foi amplamente denunciado por usuários finais. |
| **WHOIS / ARIN** | Registrado à Cloudflare, Inc.; endereços de contato de abuso (abuse@cloudflare.com) | Propriedade bem conhecida; possibilidade de **abuso de serviço** por terceiros que utilizam a CDN. |
| **Scamalytics** | Risco “low”; proxy de data‑center identificado | Confirma que o IP é de um data‑center, tornando‑o adequado para hospedagem de conteúdo legítimo ou malicioso. |
| **CVE‑2014‑3931 (referência nos metadados de alguns EXE)** | Presente nos metadados de *Err.exe* | Indicação de que alguns binários podem explorar vulnerabilidades antigas em Windows; reforça o perfil de **malware**. |

**Conclusão:** Não há evidência de que o próprio IP esteja comprometido; porém ele **serve como infraestrutura de entrega** para diversas amostras de malware e scripts possivelmente utilizados por atores maliciosos (Botnets, phishing, downloaders). O uso como CDN dificulta a atribuição direta, mas aumenta o risco de *false positives* e *collateral damage* para clientes que solicitam recursos deste IP.

## 3. Superfície de Ataque
### 3.1 Portas e Serviços Detectados (Shodan)

| Porta | Serviço / Observação |
|------|---------------------|
| 80   | HTTP – Resposta “Direct IP access not allowed \| Cloudflare”. |
| 443  | HTTPS – Resposta “400 The plain HTTP request was sent to HTTPS port”. |
| 2052 | Possível painel de controle (cPanel/WHM). |
| 2053 | Possível painel (HTTPS). |
| 2082 | cPanel non‑SSL. |
| 2083 | cPanel SSL. |
| 2086 | WHM non‑SSL. |
| 2087 | WHM SSL. |
| 2095 | Webmail (non‑SSL). |
| 2096 | Webmail SSL. |
| 8080 | HTTP alternativo (frequentemente usado por proxies ou APIs). |
| 8443 | HTTPS alternativo (geralmente admin console). |
| 8880 | Portas de teste/serviços customizados (retorna “error code: 1003”). |

> **Nota:** Nenhuma vulnerabilidade (CVE) específica relacionada a estas portas foi reportada pelos scans do Shodan. Entretanto, portas de administração abertas podem ser alvos de exploração caso os serviços subjacentes estejam mal configurados.

### 3.2 Vulnerabilidades (CVEs) Detectadas nos Arquivos Associados
| Arquivo | Tipo | CVE(s) Relacionadas |
|--------|------|----------------------|
| *Err.exe* | PE (MSIL) – AgentTesla/Variadic | **CVE‑2014‑3931** (exploração de clock em CPUs Intel) – mencionado nos metadados. |
| *SymAddressKi.exe* | PE (MSIL) – AgentTesla/Kryptik | Nenhuma CVE explicitada, mas a presença de técnicas de *anti‑debug* e *self‑delete* indica uso de exploits desconhecidos. |
| *CitizenMP.exe* (CrimeZ) | PE – Ransomware | Não há CVE listada, mas comportamento de *ransomware*. |
| *Mokes* (e6c54… .virus) | PE – Backdoor Injector | Não há CVE específica. |
| APKs (e.g., *intuitivelivinghub*, *sonarfm*) | Android | Não há CVE listada, mas contêm SDKs de anúncios e comportamentos que podem ser usados para **ad fraud** ou **downloaders**. |

> **Importante:** Apesar de não existirem CVEs diretamente exploradas nos serviços do IP, os arquivos entregues podem ter sido compilados com exploits conhecidos ou conter código que explora vulnerabilidades do sistema alvo.

## 4. Informações de Rede e Geográficas
| Item | Detalhe |
|------|---------|
| **ASN** | **AS13335** – Cloudflare, Inc. |
| **ISP** | Cloudflare, Inc. |
| **Organização** | Cloudflare, Inc. |
| **País** | United States (US) – base de registro em San Francisco, CA |
| **Cidade / Região** | San Francisco, CA |
| **Latitude / Longitude** | 37.7621 , ‑122.3971 (dados do IPInfo.io) |
| **Tipo de Rede** | Data‑center / CDN (Content Delivery Network) |
| **Uso** | Servidor de borda para múltiplos domínios (hosting, cache, C2 potencial) |

## 5. Recomendações de Ações

1. **Monitoramento Contínuo**  
   - Adicionar o IP `172.67.156.69` a um **watchlist** nos SIEM/IDS/IPS.  
   - Registrar fluxos de entrada/saída nos logs de firewall para detectar volumes anômalos ou conexões inesperadas (ex.: conexões a ports 2052‑2096 ou 8443).  

2. **Correlacionar Domínios**  
   - Utilizar feeds de **Passive DNS** para mapear todos os domínios que atualmente apontam para este IP.  
   - Priorizar inspeção de tráfego proveniente de domínios recém‑criados ou que foram associados a campanhas de phishing/malware.  

3. **Análise de Arquivos**  
   - Baixar e analisar em sandbox os arquivos listados no **VT** que têm este IP como `host`.  
   - Verificar presença de **c2** (endpoints HTTP, DNS, ou IP hard‑coded) que apontem para `172.67.156.69`.  

4. **Inspeção de Portas de Administração**  
   - Confirmar se as portas 2052‑2096, 8443 e 8880 são realmente usadas por serviços internos (ex.: cPanel/WHM). Caso não sejam necessárias, solicitar bloqueio ao provedor ou via regras de firewall.  

5. **Reportar Eventuais Abusos**  
   - Caso sejam identificados comportamentos realmente maliciosos (ex.: entrega de malware), abrir ticket de **abuse** em `abuse@cloudflare.com` com evidências (capturas de tráfego, logs, hashes).  

6. **Inteligência de Ameaças**  
   - Monitorar grupos de threat intel (e.g., AlienVault OTX, Emerging Threats) para novos indicadores que incluam **172.67.156.69** ou os hashes dos arquivos associados.  
   - Atualizar regras de detecção de **AgentTesla**, **FormBook**, **Mokes**, **Kryptik** e outras families encontradas nos binários.  

7. **Avaliação de Risco**  
   - Embora o risco atual seja classificado como **baixo**, a presença de múltiplas amostras de malware vinculadas ao IP eleva o **risco de colateral** para usuários que acessam recursos hospedados nele. Considere classificar esse IP como “**suspeito**” nos sistemas de prevenção até que a atividade seja confirmada como legítima.  

---

*Este relatório tem como objetivo apoiar equipes de segurança na tomada de decisão e reforço de monitoramento. Não contém recomendações específicas de mitigação de vulnerabilidades identificadas nos binários, conforme solicitado.*