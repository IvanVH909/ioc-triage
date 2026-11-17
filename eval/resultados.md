| IOC | Esperado | Reglas | LLM | ¿Acierta reglas? | ¿Acierta LLM? |
|---|---|---|---|---|---|
| `8.8.8.8` | benign | benign | benign | ✅ | ✅ |
| `1.1.1.1` | benign | benign | benign | ✅ | ✅ |
| `9.9.9.9` | benign | benign | benign | ✅ | ✅ |
| `google.com` | benign | benign | benign | ✅ | ✅ |
| `microsoft.com` | benign | benign | error | ✅ | - |
| `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` | malicious | malicious | error | ✅ | - |
| `8de31a9d966bf38e8267866b35ec76edd76810365d1e4b5aa510130cccc225e5` | malicious | malicious | malicious | ✅ | ✅ |
| `f8f1fcf6f77e82747fb7b2ff59c0fd47e92dd9294f52ede82dd776001b4ccaf1` | malicious | malicious | malicious | ✅ | ✅ |
| `facfeae7348bc074cd8e9ae1a5ade971df946b739987f7bcb5a2ebe11667c27f` | malicious | malicious | malicious | ✅ | ✅ |
| `226a723ffb4a91d9950a8b266167c5b354ab0db1dc225578494917fe53867ef2` | malicious | malicious | malicious | ✅ | ✅ |

**Reglas:** 10/10 aciertos (100%) · FP=0 · FN=0
**LLM:** 8/8 aciertos (100%) · FP=0 · FN=0
