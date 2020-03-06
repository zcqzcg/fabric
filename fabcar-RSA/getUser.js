'use strict';

const fs = require('fs');
const ccpJSON = require('./fabricConfig-rsa.json');
const {FileSystemWallet, X509WalletMixin, Gateway, DefaultEventHandlerStrategies} = require('fabric-network');
const fabricClient = require('fabric-client');

// 返回 org 名称
async function getOrgNameFromCcp(ccp) {
    try {
        if (!ccp.organizations) {
            throw new Error('Fabric Config File Error: Can not found "organizations".');
        }
        for (const orgs in ccp.organizations) {
            if (ccp.organizations.hasOwnProperty(orgs)) {
                return orgs;
            }
        }
    } catch (e) {
        throw new Error('getOrgNameFromCcp err: ' + e);
    }
}


// 返回 orgMSP ID
async function getOrgAdminInfos() {
    try {
        const ccp = ccpJSON;
        const orgs = await getOrgNameFromCcp(ccp);
        // 仅仅适用于 第一个 msp
        // console.log(ccp.organizations[orgs].adminPrivateKey);
        const privateKeyPem = fs.readFileSync(ccp.organizations[orgs].adminPrivateKey.path, 'utf8');
        const certificatePem = fs.readFileSync(ccp.organizations[orgs].signedCert.path, 'utf8');
        return {
            mspid: ccp.organizations[orgs].mspid,
            privateKeyPem,
            certificatePem,
        };
    } catch (e) {
        console.log(e);
        throw e;
    }
}

// 返回已经连接上的 gateway 以供使用
// 使用 ccp 提供的 admin 账户
// 调用后需要 使用 await gateway.disconnect()
async function getAdminGateway() {
    try {

        const ccp = ccpJSON;
        const {
            mspid,
            privateKeyPem,
            certificatePem,
        } = await getOrgAdminInfos();

        const wallet = new FileSystemWallet('./wallet');
        // console.log(fabricClient.getConfigSetting('crypto-suite-software'));
        // returns:
        // { EC: 'fabric-client/lib/impl/CryptoSuite_ECDSA_AES.js',
        //     RSA: 'fabric-client/lib/impl/CryptoSuite_RSA_AES.js' }
        // 强制重定向 EC 到 RSA； 默认是 EC 算法， 启动如下 configSetting 可以覆盖默认值
        fabricClient.setConfigSetting('crypto-suite-software',{EC: 'fabric-client/lib/impl/CryptoSuite_RSA_AES.js'});

        await wallet.import(
            'Org1Admin',
            X509WalletMixin.createIdentity(mspid, certificatePem, privateKeyPem)
        );

        const gateway = new Gateway();
        // const connectOptions = {};
        await gateway.connect(ccp, {
            wallet,
            identity: 'Org1Admin',
            discovery: {enabled: false},
            eventHandlerOptions: {
                strategy: DefaultEventHandlerStrategies.MSPID_SCOPE_ALLFORTX
            },
        });
        console.log('get Org1Admin Gateway and connected successfully!');
        return gateway;
    } catch (e) {
        console.log(e);
        throw e;
    }
}

getAdminGateway();
module.exports = {
    getOrgAdminInfos,
    getAdminGateway
}
