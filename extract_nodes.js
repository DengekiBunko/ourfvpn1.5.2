const https = require('https');
const crypto = require('crypto');

const PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCUHMdMJFSzOnuO
OIRY3UZcWTXfCexZ15UOXjZB8fvgLxyvTN5gTh+Wo6SNb48ojuIw/p3fltMom3ZW
eyeKD5QB/sL+LgWHs10GrCE73TYwsmhdXUCyZhZX7VK8meqsFBBf7SDTPcJ6lfup
XsFstxQWV9nq2FQAQLSzUVU46KGjADKV7cEwamQ+C+0ix74EfDYvaZohfUtHEMie
MB5xYePJnxPS1qqP4Ftsgco5/hZfscsf9lR4+LSDAj+krNRo2j6Kto030Kxrwymi
7KbfVvlXujYsoh+LlhEXEAxHYUTbllKvcKRWvEiMNkW64+lFMclVIkHs0KjRPrOY
0nfy0iVJAgMBAAECggEAQdrP5HOM84nv0OshMW/lbn89/Dcpz0KTJGnQXx7seqAH
9YvMnm5uDikhq79sHED3oog7guRJbBc/lTE6AeFuUjrH0YN98vnVxXc4aakwhJN2
4vhpIUlR6vN7I5+eH7fmFfjV7QbbV20jkgmvIBsBA/Q40Pox01Dx538k0OJiqBnr
h+jdL99lURPYkG3/mfT3R2pG+vIP2PYydW0pi87f6AK4pxFZnAF82MuGcCM+Byr0
ga8/pSV4wmkU+kezK4P6RfbSi4tuUszvaBWcczAgqEN3yltYwN0v/JSk2oHcBSx4
phJV/RGGGg/IRHt4d0zi3PRfTrx2YI7AEgc1TCVSxwKBgQDMTdr6j64IMtWM45TG
QMcwtZLDutdCpvkVBGtpzdj3DWP2ZYAWQoO1ko1T2IOKkNWIXO3PEmX2fnTvyERk
XPQeiLf085TNnfnzKvCG8DrQwHZqdb2Wt1M2FJkYvxd14CALK2l6yHUEAyNveUoD
VcmtOapYvCndo9d7JpmoiCzelwKBgQC5lwKqyhwLEvbKegMMSZKrL5AsdKbp/r/r
Vovgw2wBhtmj7Gr8bnkS9nAmI3mETCFolxmbDHPK2Yt6D/+LtIcOdalI6Ox93nHx
IV2kPQff5czWa78IiiGPeJYrp/ZBZK33egWJWPAsQsZAms0GXAQ9vSomUUBi8rUT
Lkc03c13HwKBgQCsSqv0yd5WA6ib3ADHADH7HeTbM2H9T5qW4tdCrtnd3mkCja5r
F0TDhwewQdMMs/+fs97I1hcuvI4Y+KbUjJ9CcMHRzOkcTbFQJFIbOdQf3279cLWl
uIxv+wbxG5XJTm03fjDB3vLvo0Xq6DpGfb5KW2sQ0f3scBN0Q6Upv003mQKBgFPk
oG8Fx6F15BtpBiGyzFsXuAtwe9dAsg6246opjJQwGgfQohgT9CUPQ2jqFk8oft2h
mBCPk3Q53KPDwZesdnSh2XE84VKQkF8Y3xSUBhA+99ZhhExe7IbHUtLPLTEoSr+Y
6BHLI15OnQGtOErMo5oo/XmutvVDk3jlLYkHTo6vAoGBAKaT2qIDOStdCrwRbvD1
SF/pcEytM0rQhiJYmBXKeayUsICTxnSdixb42BSRDTL14F6Jzv2GcGRh80Jx1DVL
6Dmv27MEXx3OnCiHmTCHi3CxqKXhOvJGQCbtLLjluP6pAvQCZ7s3KB6/zS4v/fIv
zygLJrETnjWa1iAMPLnIB9lB
-----END PRIVATE KEY-----`;

const CONFIG_URLS = [
  'https://gitlab.com/zhifan999/fq/-/raw/main/config.json',
  'https://www.githubip.xyz/config.json'
];

function fetchUrl(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { timeout: 10000 }, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => resolve(data));
    }).on('error', reject).setTimeout(10000);
  });
}

function pemToBuffer(pem) {
  const clean = pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
  return Buffer.from(clean, 'base64');
}

async function decryptConfig(envelope) {
  const privateKey = crypto.createPrivateKey(PRIVATE_KEY_PEM);
  
  const encryptedKey = Buffer.from(envelope.key, 'base64');
  const aesKey = crypto.privateDecrypt(
    { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' },
    encryptedKey
  );
  
  const iv = Buffer.from(envelope.iv, 'base64');
  const encryptedData = Buffer.from(envelope.data, 'base64');
  
  const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
  let decrypted = decipher.update(encryptedData);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  
  return JSON.parse(decrypted.toString());
}

function generateClashConfig(nodes) {
  const proxies = nodes.map(node => ({
    name: node.name || `节点-${node.server}`,
    type: 'https',
    server: node.server,
    port: node.port,
    tls: true,
    skip_cert_verify: true
  }));
  
  const groups = [
    {
      name: '自动选择',
      type: 'url-test',
      proxies: proxies.map(p => p.name),
      url: 'http://www.gstatic.com/generate_204',
      interval: 300
    }
  ];
  
  return {
    proxies,
    'proxy-groups': groups,
    rules: [
      'DOMAIN-SUFFIX,cn,DIRECT',
      'GEOIP,CN,DIRECT',
      'MATCH,自动选择'
    ]
  };
}

function generateV2rayNPlain(nodes) {
  return nodes.map(node => {
    return `${node.name || node.server} = https,${node.server},${node.port}`;
  }).join('\n');
}

function generateSubscriptionUrl(config) {
  const base64 = Buffer.from(JSON.stringify(config)).toString('base64');
  return `data:application/json;base64,${base64}`;
}

async function main() {
  console.log('=== FanVPN 节点提取工具 ===\n');
  
  let envelope = null;
  for (const url of CONFIG_URLS) {
    try {
      console.log(`尝试从 ${url} 获取配置...`);
      const data = await fetchUrl(url);
      envelope = JSON.parse(data);
      console.log('✓ 配置获取成功');
      break;
    } catch (e) {
      console.log(`✗ 失败: ${e.message}`);
    }
  }
  
  if (!envelope) {
    console.log('\n✗ 所有配置源都失败了');
    process.exit(1);
  }
  
  console.log('\n正在解密配置...');
  const config = await decryptConfig(envelope);
  console.log(`✓ 解密成功，共 ${config.nodes.length} 个节点`);
  
  console.log('\n=== 节点列表 ===');
  config.nodes.forEach((node, index) => {
    console.log(`${index + 1}. ${node.name} (${node.flag}) - ${node.server}:${node.port}`);
  });
  
  console.log('\n=== 生成配置文件 ===');
  
  const clashConfig = generateClashConfig(config.nodes);
  require('fs').writeFileSync('./clash_config.yaml', JSON.stringify(clashConfig, null, 2));
  console.log('✓ Clash 配置已保存到 clash_config.yaml');
  
  const plainConfig = generateV2rayNPlain(config.nodes);
  require('fs').writeFileSync('./v2rayn_proxy.txt', plainConfig);
  console.log('✓ V2RayN 格式已保存到 v2rayn_proxy.txt');
  
  const subUrl = generateSubscriptionUrl(clashConfig);
  console.log('\n=== 订阅链接 (Clash格式) ===');
  console.log(subUrl);
  console.log('\n提示: 由于是HTTPS代理协议，v2rayn原生不支持。建议使用Clash或在v2rayn中配合使用Socks转HTTPS工具。');
}

main().catch(console.error);