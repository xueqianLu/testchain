
/**
 * 16进制转10进制
 * @param {*} hex 
 * @returns 
 */
function HexToDec(hex){
    hex = hex.replace("0x","");
    var len = hex.length, a = new Array(len), code;
    for (var i = 0; i < len; i++) {
        code = hex.charCodeAt(i);
        if (48<=code && code < 58) {
            code -= 48;
        } else {
            code = (code & 0xdf) - 65 + 10;
        }
        a[i] = code;
    }
     
    return a.reduce(function(acc, c) {
        acc = 16 * acc + c;
        return acc;
    }, 0);
}



function switchNetWork() { 
    if (typeof window.ethereum === "undefined") {
        alert("Please Install MetaMask!");
        return;
    } 
    let hpbTestnet = {
        chainId: "0x10d",
        chainName: "HPB Mainnet",
        rpcUrls: ["https://hpbnode.com"], //http://114.242.26.15:8006
        blockExplorerUrls: ["https://hscan.org"],
        nativeCurrency: {
            name: "High Performance Blockchain Ether",
            symbol: "HPB",
            decimals: 18
        }
    };
    switchChain(hpbTestnet);
}
async function addChain(data) {
    try {
        await window.ethereum.request({
            "id": 1,
            "jsonrpc": "2.0",
            "method": "wallet_addEthereumChain",
            params: [data],
        });
    } catch (addError) {
        console.log(1,addError)
        // handle "add" error
    }
}
async function switchChain(data) {
    try {
        let {chainId} = data;
        await window.ethereum.request({
            method: 'wallet_switchEthereumChain',
            params: [{chainId}],
        });
    } catch (switchError) { 
        // This error code indicates that the chain has not been added to MetaMask.
        // console.log(switchError)
        if (switchError.code === 4902) {
            addChain(data);
        }
        // handle other "switch" errors
    }
}

async function getWallet() {
 
   
    if (typeof window.ethereum === "undefined") {
        alert("Please Install MetaMask!");
        return;
    } 
    let account = ""; 
    const ethereum = window.ethereum
    if (ethereum) {
       let {selectedAddress,chainId} =  ethereum 
       if (!selectedAddress) {
           const accounts = await ethereum.enable();  
           console.log('accounts',accounts)
       } 
       selectedAddress =ethereum.selectedAddress 
       chainId =ethereum.chainId  
        if (selectedAddress) {
            account = selectedAddress ;//ethereum._state.accounts[0];
            if (account) {  
                if (chainId && chainId.length > 0) {
                    let chId = parseInt(chainId, 16);
                    if(chId !==269){
                        switchNetWork()
                    }         
                }  
            }
        }
 
    }   
}
function createComprisonFunctionAsc (propName) {
	return function (object1, object2) {
		var value1 = object1[propName];
		var value2 = object2[propName];
		if (value1 < value2) {
			return -1;
		} else if (value1 > value2) {
			return 1;
		} else {
			return 0;
		}
	}
} 
function createComprisonFunctionDesc (propName) {
	return function (object1, object2) {
		var value1 = object1[propName];
		var value2 = object2[propName];
		if (value1 > value2) {
			return -1;
		} else if (value1 < value2) {
			return 1;
		} else {
			return 0;
		}
	}
} 
function compareObjAsc(prop){
    return function(obj1,obj2){
        var val1 = obj1[prop].replace("%","");
        var val2 = obj2[prop].replace("%","");
        if(!isNaN(Number(val1))&& !isNaN(Number(val2))){
            val1 = Number(val1);
            val2 = Number(val2);
            return val1 -val2;
        }else{
            return val1 > val2;
        }
       

    }
}
function compareObjDesc(prop){
    return function(obj1,obj2){
        var val1 = obj1[prop].replace("%","");
        var val2 = obj2[prop].replace("%","");
        if(!isNaN(Number(val1))&& !isNaN(Number(val2))){
            val1 = Number(val1);
            val2 = Number(val2);
            return val2 - val1;
        }else{
            return val2 > val1;
        }
        

    }
}
/*字符串加密*/
function encrypt(txt) {
    if (!txt) return txt;
    var rt = [];
    var i, s, l = txt.length;
    s = (l + 10).toString(36);
    rt.push((s.length + 10).toString(21) + s);
    for (i = 0; i < l; i++) {
        s = (txt.charCodeAt(i) + (i + 1) * 10 + l).toString(36);
        rt.push((s.length + 10).toString(21) + s);
    }
    return rt.join('');
}
export  {
    HexToDec,
    switchNetWork,
    compareObjAsc,
    compareObjDesc,
    encrypt,
    getWallet,
    createComprisonFunctionAsc,
    createComprisonFunctionDesc
}