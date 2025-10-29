# Relatório de Threat Intelligence – IP **34.143.73.2**

> **Fonte dos dados**: Shodan, IPInfo.io, ARIN / RIPE RDAP, URLScan.io (sem resultados).  
> **Última coleta Shodan**: 2025‑10‑28.  

---

## 1. Resumo Executivo
O endereço **34.143.73.2** pertence à faixa de IPs da Google Cloud (ASN AS396982) e está localizado em **Mountain View, Califórnia, EUA**. Nos últimos dias o host apresentou **portas 80/tcp e 443/tcp** abertas, respondendo com mensagens **HTTP 404 Not Found**. O certificado TLS exibido é **auto‑assinado**, com validade de 2015‑01‑01 a 2030‑01‑01, indicando que não há um certificado válido emitido por uma autoridade certificadora reconhecida. Não foram identificadas vulnerabilidades (CVEs) associadas ao host e não há indícios claros de atividade maliciosa (botnet, C2 ou scanner) nos dados analisados.

---

## 2. Análise de Comportamento
| Fonte | Evidência | Interpretação |
|-------|-----------|--------------|
| **Shodan** | Portas 80 e 443 abertas; resposta HTTP 404; tag *self‑signed* | Serviço web/HTTPS ativo, mas sem conteúdo público (404). O certificado auto‑assinado pode indicar uso interno ou teste. |
| **IPInfo.io** | Organização “Google LLC”, ASN AS396982, localização “Mountain View, CA” | IP alocado para infraestrutura Google Cloud – uso típico por clientes da GCP. |
| **ARIN / RDAP** | Registro mostra que a faixa **34.128.0.0/10** pertence à Google (GOOGL‑2) e que “os endereços estão em uso por clientes Google Cloud”. | Não há indicação de propriedade maliciosa direta. |
| **URLScan.io** | Não há resultados associados ao IP (nenhum URL capturado). | Falta de tráfego público ou de análise de URLs apontando para este IP. |
| **Análise de vulnerabilidades** | Nenhuma CVE listada no Shodan. | Não há vulnerabilidades conhecidas divulgadas para os serviços expostos (Apache/Nginx etc.). |

**Conclusão comportamental**: O host parece ser um ponto de terminação de infraestrutura de nuvem (possivelmente usado por um cliente da Google Cloud para hospedagem de serviços web ainda não configurados ou em fase de teste). Não foram encontradas evidências de comunicação com botnets, servidores de C2 ou de scanners automatizados.  

---

## 3. Superfície de Ataque

### 3.1 Portas abertas e serviços
| Porta | Serviço | Observação |
|-------|---------|------------|
| **80/tcp** | HTTP‑Server ( Apache/Nginx ou outro ) | Responde com `404 Not Found`. |
| **443/tcp** | HTTPS – TLS/SSL (certificado auto‑assinado “invalid2.invalid”) | Também devolve `404`. Certificado com **CA:TRUE** (auto‑assinado), validade 2015‑01‑01 → 2030‑01‑01. |

### 3.2 Vulnerabilidades (CVEs) identificadas
- **Nenhuma** vulnerabilidade conhecida foi reportada pelo Shodan para este endereço.  

---

## 4. Informações de Rede e Geográficas

| Campo | Valor |
|-------|-------|
| **ASN** | AS396982 – Google Cloud Platform |
| **Provedor (ISP)** | Google LLC |
| **Organização** | Google LLC |
| **País** | United States (EUA) |
| **Região / Estado** | California |
| **Cidade** | Mountain View |
| **Latitude / Longitude** | 38.0088, ‑122.1175 |
| **Anycast** | Sim (IP anycast da Google) |

---

## 5. Recomendações de Investigação

1. **Correlacionar logs de firewall / IDS**  
   - Verificar se há tráfego de entrada/saída para `34.143.73.2` em seus sensores de perímetro.  
   - Identificar volume, protocolos, e possíveis padrões de varredura ou exfiltração.

2. **Consultar feeds de Threat Intelligence**  
   - Inserir o IP nos principais feeds (VirusTotal, AbuseIPDB, AlienVault OTX, etc.) para detectar eventual inclusão futura.  
   - Configurar alertas automáticos para mudanças de classificação.

3. **Analisar conexões TLS**  
   - Monitorar sessões TLS para detectar uso do certificado auto‑assinado; isso pode indicar a presença de um serviço interno que ainda não recebeu um certificado válido.

4. **Verificar reputação de domínios associados**  
   - Embora nenhum domínio tenha sido resolvido para este IP nos dados analisados, caso algum domínio comece a apontar para ele, revisite a análise imediatamente.

5. **Aplicar políticas de whitelist/blacklist**  
   - Se o tráfego ao IP for inesperado, considerar bloqueio temporário até que a origem seja confirmada.  
   - Caso o IP seja utilizado por serviços corporativos internos, validar a necessidade da exposição das portas 80/443.

6. **Realizar varredura de vulnerabilidades interna**  
   - Executar scans de vulnerabilidade (ex.: Nessus, OpenVAS) nos serviços HTTP/HTTPS para confirmar a ausência de vulnerabilidades não divulgadas publicamente.

7. **Monitorar alterações no certificado**  
   - Configurar monitoramento de transparência de certificados (CT logs) para ser notificado caso o certificado seja trocado por um emitido por CA pública.

---

### Nota final
Com base nas evidências disponíveis, **não há indicações fortes de atividade maliciosa** associada ao IP **34.143.73.2**. Entretanto, a presença de um certificado auto‑assinado e respostas 404 pode indicar que o servidor está em fase de implantação ou sendo usado como ponto de teste. Acompanhar o comportamento do host nos próximos dias e aplicar as recomendações acima garantirá que qualquer mudança de perfil seja rapidamente detectada.