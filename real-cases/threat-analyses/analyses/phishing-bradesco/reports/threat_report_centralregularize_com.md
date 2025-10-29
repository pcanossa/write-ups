# Relatório de Threat Intelligence – Domínio **centralregularize.com**

> **Fonte dos dados**: WHOIS.com, URLScan.io, VirusTotal.  
> **Última coleta VirusTotal**: 2025‑10‑29T17:32:52.906Z (escaneamento URLScan) – dados VT atuais mostram última análise em 2025‑10‑07.

---

## 1. Resumo Executivo
O domínio **centralregularize.com** foi registrado em 4 de outubro 2025 (GoDaddy) e ainda possui idade de poucos dias (1 – 24 dias, dependendo da fonte). Os registros DNS apontam para dois IPs distintos: **191.252.225.147** (Locaweb – Brasil, ASN AS27715) e **161.35.50.50** (DigitalOcean – EUA, ASN AS14061). Os mecanismos de análise de URL e de arquivos (VirusTotal) classificam o domínio como *harmless* (0 malicious, 0 suspicious, 62 harmless, 33 undetected). O conteúdo apresentado nas duas varreduras corresponde a um blog de café em português, sem indícios de phishing, C2 ou distribuição de malware. Contudo, a recente criação, a troca frequente de IPs e a presença em duas infra‑estruturas diferentes justificam monitoramento contínuo, pois domínios recém‑criados são comumente empregados em campanhas maliciosas antes de serem detectados.

---

## 2. Análise de Comportamento
| Fonte | Indicador | Avaliação |
|-------|-----------|-----------|
| **URLScan.io** (02/10/2025) | *Redirected: https‑only*; **TLS** válido por 89 dias (Let's Encrypt R12). | Boas práticas de TLS, porém certificado recém‑emitido (ponto de atenção típico de domínios “lavados”). |
| URLScan.io (29/10/2025) | Servidor **Apache/2.4.58 (Ubuntu)**, idioma **pt**, título **Giovani e Adenir Oliveira: da terra ao seu paladar — Blog Veroo Cafés**. | Conteúdo de blog legítimo, sem scripts suspeitos visíveis nos relatórios resumidos. |
| **VirusTotal** – *last_analysis_results* | 62 engines “harmless”, 33 engines “undetected”, 0 malicious. | Nenhum motor de AV detectou ameaça. |
| **DNS** | **NS17/NS18.DOMAINCONTROL.COM** (GoDaddy). | Nameservers padrão de registrador – sem evidência de DNS hijacking. |
| **ASN / IP** | US – **AS14061 (DigitalOcean)**; BR – **AS27715 (Locaweb)**. | Dois provedores diferentes; pode indicar uso de CDN, load‑balancer ou mudança rápida de hospedagem. |
| **Domínio recém‑criado** (≤ 24 dias) | Domínios novos costumam ser usados em **phishing**, **malspam**, ou como **C2** temporário antes de serem bloqueados. | Atenção ao potencial de uso futuro, apesar do contexto atual benigno. |

**Conclusão comportamental:** Nenhum indicativo de atividade maliciosa confirmada nos dados atuais. O domínio parece hospedar um blog legítimo, mas a rápida mudança de IP e a idade mínima sugerem que o domínio ainda pode ser recrutado por atores maliciosos.

---

## 3. Informações de Rede e Geográficas
| Campo | Valor |
|-------|-------|
| **ASN** | **AS14061** – *DIGITALOCEAN‑ASN, US* (para IP 161.35.50.50) <br> **AS27715** – *Locaweb Serviços de Internet SA, BR* (para IP 191.252.225.147) |
| **ISP / Provedor** | DigitalOcean (EUA) <br> Locaweb (Brasil) |
| **Localização (IP 161.35.50.50)** | **Estados Unidos** – região não especificada (provavelmente Norte‑Vermont, conforme dados de GeoIP comuns). |
| **Localização (IP 191.252.225.147)** | **Brasil**, província **São Paulo** (PTR indica `vpscl3417.publiccloud.com.br`). |
| **Cidade / Estado / País** | Não há cidade específica nos dados WHOIS; a localização IP indica US e BR. |
| **Registro de Domínio** | Registrador **GoDaddy.com, LLC** (ID 146), criado em **04‑Oct‑2025**, expira **04‑Oct‑2026**. |
| **Nameservers** | `ns17.domaincontrol.com`, `ns18.domaincontrol.com`. |

---

## 4. Domínios e IPs Relacionados

| Tipo | Valor | Observação |
|------|-------|------------|
| **Domínio analisado** | `centralregularize.com` | Registrado 04‑Oct‑2025. |
| **Nameservers** | `ns17.domaincontrol.com` <br> `ns18.domaincontrol.com` | Padrão GoDaddy. |
| **Endereço IPv4 – 1** | `191.252.225.147` | Locaweb (BR), **AS27715**, hostname `vpscl3417.publiccloud.com.br`. |
| **Endereço IPv4 – 2** | `161.35.50.50` | DigitalOcean (US), **AS14061**. |
| **TLS Issuer** | Let’s Encrypt **R12** | Certificado emitido em 04‑Oct‑2025, validade 89 dias. |
| **Sub‑domínios conhecidos** | *(nenhum identificado nas varreduras públicas; recomendável monitorar registros DNS futuros).* |
| **Domínios correlacionados** | `domaincontrol.com` (hosts dos NS) – não diretamente suspeitos. |
| **Hash de JARM** | `15d3fd16d29d29d00042d43d000000ad5982e0c23bdf2bdf34e47480ccc0a3` (para o IP US). | Pode ser usado para fingerprint de servidores e verificação de mudanças. |

---

## 5. Recomendações de Investigação

1. **Monitoramento de DNS**  
   - Configurar um *DNS watch* (e.g., `dnstwist`, `SecurityTrails`, ou serviço de DNS passive DNS) para detectar alterações de IP ou novos registros (A, AAAA, CNAME, MX).  
   - Alertar caso o domínio passe a apontar para IPs associados a listas de má reputação ou a serviços de *cloud* conhecidos por hospedar botnets.

2. **Análise de tráfego Web**  
   - Capturar o *traffic* HTTP(S) real (via proxy ou sandbox) e analisar recursos externos (scripts, iframes, chamadas a APIs externas).  
   - Verificar presença de *web‑beacon* ou chamadas a domínios de reputação baixa.

3. **Cross‑checking em feeds de ameaças**  
   - Consultar feeds como **AbuseIPDB**, **urlhaus**, **malwaredomains.com**, **OTX**, **AlienVault OTX** para os IPs `191.252.225.147` e `161.35.50.50`.  
   - Registrar eventuais inclusões futuras.

4. **Inspeção de certificado TLS**  
   - Verificar renovação automática do certificado Let’s Encrypt; domínios maliciosos costumam usar certificados auto‑assinados ou rapidamente renovados para evitar bloqueios.

5. **Análise de reputação de WHOIS**  
   - Checar a **historical WHOIS** para possíveis mudanças de contato ou proprietário (e.g., “privacy protection” ativado).  
   - Confirmar se o registrante usa serviço de privacidade; isso pode ser sinal de anonimato malicioso.

6. **Correlações com outros indicadores**  
   - Buscar por menções ao domínio em listas de *phishing* ou *spam* (e.g., PhishTank, Spamhaus).  
   - Avaliar se a combinação de *IP + ASN* já aparece em campanhas anteriores (por exemplo, trojans hospedados em servidores DigitalOcean).

7. **Planejar ação de bloqueio** (se necessário)  
   - Caso futuro comportamento suspeito seja detectado, instruir equipes de SOC a adicionar IPs ao *blocklist* interno e a atualizar regras de *Web Proxy* / *Firewall*.  

---

## 6. Conclusão
Atualmente, **centralregularize.com** demonstra um perfil **benigno**: registro recente, certificado TLS válido, conteúdo de blog em português e ausência de detecções por mecanismos antivírus. Contudo, a **idade curta** do domínio e a **variação de hospedagem entre Brasil e EUA** são características típicas de domínios que podem ser usados temporariamente em campanhas de phishing ou como *droppers* antes de serem marcados. Recomendamos **monitoramento ativo** e integração aos fluxos de inteligência de ameaças para garantir que eventuais mudanças de comportamento sejam rapidamente identificadas e mitigadas.

--- 

*Este relatório destina‑se a profissionais de segurança da informação e equipes de Threat Intelligence para avaliação de risco de terceiros.*