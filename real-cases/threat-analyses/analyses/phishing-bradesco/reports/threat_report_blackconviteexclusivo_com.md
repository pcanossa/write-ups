# Relatório de Threat Intelligence – Domínio **blackconviteexclusivo.com**

> **Fonte dos dados**: WHOIS.com, URLScan.io, VirusTotal.  
> **Última coleta VirusTotal**: 2025‑10‑06  (timestamp = 1759709094).  

---

## 1. Resumo Executivo
O domínio **blackconviteexclusivo.com** foi registrado em 26 / 09 / 2025 via GoDaddy (registrar ID 146) com proteção de privacidade de quem registra (Domains By Proxy). O A‑record aponta para o IP **191.252.227.30**, pertencente ao ASN **AS27715 – Locaweb Serviços de Internet SA (BR)**, um provedor de hospedagem brasileiro. O site está ativo, entrega um conteúdo em português (um blog de cafés) e utiliza certificado **Let’s Encrypt R13** válido por 89 dias. 

Embora o **VirusTotal** classifique o domínio como “clean” (0 malicious, 0 suspicious) e a maioria das engines o rotule como “harmless”, o **URLScan.io** o marcou com a tag **“suspect”**, possivelmente devido à sua idade (criado há menos de 1 dia) e ao fato de ser um domínio recém‑lançado que ainda não possui reputação consolidada. Não há evidências diretas de atividades de C2, botnet ou phishing, mas o perfil (domínio novo, hospedado em um provedor de baixo custo, certificado gratuito) combina com padrões frequentemente observados em infraestruturas preparatórias de campanhas maliciosas.

---

## 2. Análise de Comportamento

| Indicador | Evidência | Interpretação |
|-----------|-----------|---------------|
| **Idade do domínio** | Criado em 26 / 09 / 2025 (0 dias) | Alta probabilidade de uso inicial para campanha; domínios recém‑criados costumam ser empregados em phishing ou distribuição de malware antes de serem bloqueados. |
| **Tag “suspect” (URLScan.io)** | Aplicada ao resultado da varredura. | Indica que a comunidade de análise suspeita do site, possivelmente por comportamento anômalo (ex.: redirecionamento “HTTPS‑only”, uso de CDN/serviços de anonimato). |
| **Detecção em VT** | 0 malicious, 0 suspicious; 61 harmless, 34 undetected. | Nenhum engajamento conhecido até o momento, porém a ausência de detecção não garante ausência de risco. |
| **Conteúdo** | Blog “Giovani e Adenir Oliveira: da terra ao seu paladar — Blog Veroo Cafés”. | Aparente site legí­mo (conteúdo de blog). No entanto, a página pode ser um “front” para redirecionamentos futuros ou download de payloads. |
| **Servidor** | Apache 2.4.52 (Ubuntu) | Software popular, não indica nada suspeito por si só. |
| **Certificado** | Let’s Encrypt (R13), validade 26 / 09 / 2025 → 25 / 12 / 2025. | Certificados gratuitos são comuns em campanhas de phishing para garantir HTTPS sem custo adicional. |
| **ASN / ISP** | AS27715 – Locaweb Serviços de Internet SA (BR) | Provedor de hospedagem brasileiro, usado por muitos sites legítimos, mas também por atores maliciosos que buscam servidores com pouca restrição. |
| **IP 191.252.227.30** | Único A‑record. | Não há histórico público de reputação de IP (não listado em feeds de malwares conhecidos). Entretanto, o IP pode hospedar múltiplos domínios; monitoramento futuro recomendado. |

### Conclusão de comportamento
Até o momento não há **provas concretas** de que **blackconviteexclusivo.com** seja usado como infraestrutura de C2, botnet ou phishing ativo. Contudo, **o perfil de novo domínio, hospedado em um provedor de baixo custo e com certificado gratuito**, aliado à **tag “suspect”**, o coloca em uma **zona de atenção** para observação contínua.

---

## 3. Informações de Rede e Geográficas

| Campo | Valor |
|-------|-------|
| **ASN** | **AS27715 – Locaweb Serviços de Internet SA (BR)** |
| **Provedor (ISP)** | **Locaweb Serviços de Internet SA** (Brasil) |
| **IP** | **191.252.227.30** |
| **Localização** | **Brasil – Estado não especificado (provavelmente São Paulo ou Minas Gerais, região de data‑center da Locaweb)** |
| **Cidade** | Não especificada pelo WHOIS; provedor normalmente opera em São Paulo (SP). |
| **País** | **BR (Brasil)** |

---

## 4. Domínios e IPs Relacionados

| Tipo | Valor | Observação |
|------|-------|------------|
| **IP atual do domínio** | 191.252.227.30 | Único A‑record. |
| **Outros domínios no mesmo IP** | Não identificados nos dados fornecidos. Recomenda‑se consulta a serviços de “reverse‑IP lookup” (ex.: SecurityTrails, Shodan, Censys) para mapear possíveis pares. |
| **Domínios “siblings” (registrar/registrant)** | Qualquer domínio registrado via **DomainsByProxy** (privado) pode estar associado; sem lista pública. |
| **Servidores de nomes** | ns69.domaincontrol.com, ns70.domaincontrol.com | Operados por GoDaddy (DomainControl). |
| **Certificado alternativo (SAN)** | Apenas **blackconviteexclusivo.com** – sem outros SANs. |

---

## 5. Recomendações (Investigação)

1. **Monitoramento contínuo**  
   - Adicionar o domínio e o IP a **watchlists** de sua plataforma SIEM/EDR.  
   - Configurar alertas de *DNS query* e *HTTP request* envolvendo o domínio/IP.

2. **Análise de tráfego**  
   - Verificar logs de firewall/proxy para conexões originadas ou destinadas a **191.252.227.30**.  
   - Correlacionar com outros indicadores de comprometimento (IOC) internos.

3. **Consulta a feeds de ameaças**  
   - Checar regularmente o domínio/IP em fontes como AbuseIPDB, AlienVault OTX, MalwareBazaar, URLhaus, PhishTank, e feeds de **Rapid7** ou **GreyNoise**.  

4. **Reverse‑IP lookup**  
   - Utilizar serviços como **SecurityTrails**, **Shodan**, **Censys** ou **BinaryEdge** para descobrir outros domínios hospedados no mesmo IP. Avaliar se algum deles já aparece em listas de bloqueio.

5. **Análise de conteúdo**  
   - Baixar o HTML da página (via sandbox) e analisar scripts, redirects e recursos externos (ex.: CDN, trackers).  
   - Verificar se há *obfuscated JavaScript* ou chamadas a serviços de comando remoto.

6. **Teste de reputação de certificado**  
   - Embora o certificado Let’s Encrypt seja legítimo, confirmar que o **JARM fingerprint** corresponde ao esperado para a infraestrutura da Locaweb.

7. **Investigação de WHOIS privado**  
   - Se necessário, submeter solicitação de *Abuse* ao registrar **GoDaddy** (e‑mail abuse@godaddy.com) para obter informações adicionais ou relatar comportamento suspeito.

8. **Planejamento de resposta**  
   - Caso futuras análises detectem atividade maliciosa (ex.: download de payloads, phishing), preparar bloqueio de rede imediato e notificação ao provedor de hospedagem (Locaweb) e ao registrar.

---

## 6. Conclusão

*blackconviteexclusivo.com* ainda não apresenta indicadores de comprometimento ativo, mas sua **idade extremamente baixa**, hospedagem em um provedor de baixo custo e a **marcação “suspect”** por URLScan.io são sinais de alerta que justificam observação constante. Recomenda‑se incluir o domínio e seu IP nas rotinas de monitoramento de ameaças, correlacionar com tráfego interno e mapear outros recursos que possam compartilhar a mesma infraestrutura. 

---