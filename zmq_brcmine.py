import os
import time
import zmq
import threading
import requests
import queue
import concurrent.futures  # Ensure this line is here
import traceback

from bitcoinutils.script import Script
from bitcoinutils.transactions import Transaction, TxOutput, TxInput
from bitcoin.core.script import CScript
from bitcoin.core import lx, b2lx, b2x, x
from dotenv import load_dotenv

load_dotenv()

# A global list of txid we RBF'd so we dont bump them again
rbf_txids = []

def is_p2tr_outpint(decoded_script):
    asm_field = decoded_script.get('asm', '')
    if asm_field.startswith('1'):
        return True
    return False



def send_rpc_request(method, params=[]):
    url = "http://127.0.0.1:8332"
    headers = {'content-type': 'text/plain;'}
    rpc_user = os.getenv("BITCOIN_RPC_USER")
    rpc_password = os.getenv("BITCOIN_RPC_PASS")
    data = {
        "jsonrpc": "1.0",
        "id": "bitcoin-python",
        "method": method,
        "params": params
    }

    response = requests.post(url, headers=headers, json=data, auth=(rpc_user, rpc_password))
    return response.json()['result']

def check_inner_witness(txid):
    print(txid)
    missing_sigs_tx = []

    if txid in rbf_txids:
        print(f"Found an already existing tx {txid}")
        return missing_sigs_tx

    # Getting the raw transaction data from bitcoin core
    raw_tx = send_rpc_request("getrawtransaction", [txid])
    if not raw_tx:
        return missing_sigs_tx

    # Decoding the raw transaction data
    decoded_tx = send_rpc_request("decoderawtransaction", [raw_tx])
    if not decoded_tx:
        return missing_sigs_tx

    for vin in decoded_tx['vin']:
        # Fetch the txid and vout for the input
        input_txid = vin['txid']
        output_index = vin['vout']

        # Fetch the raw transaction for the input txid
        raw_input_tx = send_rpc_request("getrawtransaction", [input_txid])
        if not raw_input_tx:
            print(f"No raw transaction found for txid: {input_txid}")
            continue

        # Decode the raw transaction data
        decoded_input_tx = send_rpc_request("decoderawtransaction", [raw_input_tx])
        if not decoded_input_tx:
            print(f"Unable to decode raw transaction for txid: {input_txid}")
            continue

        # Fetch the script for the corresponding output index
        try:
            script = decoded_input_tx['vout'][output_index]['scriptPubKey']
        except IndexError:
            print(f"No output found at index {output_index} for txid: {input_txid}")
            continue

        # Check to see if the output to the input is p2tr
        if is_p2tr_outpint(script):
            ''' First lets make a change address that we can use an sign for, create inputs and outputs '''
            #Get a UTXOs ready to bump the TX
            utxos = send_rpc_request("listunspent")
            selected_utxos = []
            change_value = 0
            # Iterate through unspent transactions
            for tx in utxos:
                #amount is less than 1000, add txid and vout to the array
                if tx['amount'] > .00002000:
                    selected_utxos.append(TxInput(tx['txid'], tx['vout']))
                    change_value += tx['amount']
            if not selected_utxos:
                return missing_sigs_tx
            # Next lets get ourselves a change address
            change_address = send_rpc_request("getnewaddress")
            change_value *= 100000000
            # Get the script pubkey
            address_details = send_rpc_request("validateaddress", [change_address])
            try:
                change_txout = TxOutput(int(change_value) - 1777, Script.from_raw(address_details['scriptPubKey']))
            except Exception as E:
                print(f'Failed to generate change output with error {E}')

            print(change_txout)

            # Decode the [0] index witness script
            txinwitness = vin.get('txinwitness', [])

            if len(txinwitness) > 1:
                # Take the first witness script
                witness_script = txinwitness[-2]

                # Call the decodescript RPC with the witness script
                decoded_script = send_rpc_request("decodescript", [witness_script])
                # data you want to include in OP_RETURN output
                data = 'Acid Burn - Portland.HODL & D++'  # make sure it is within the allowed byte limit
                #data = 'Portland.HODL was here.'  # make sure it is within the allowed byte limit
                data_bytes = data.encode('utf-8')
                hex_data = data_bytes.hex()

                # construct OP_RETURN output script
                op_return_script = Script(['OP_RETURN', hex_data])
                outpoint = TxOutput(0, op_return_script)
                # Print the decoded script result
                if 'OP_CHECKSIG' not in str(decoded_script.get('asm', "")):
                    # Create a TX object
                    py_tx = Transaction.from_raw(raw_tx)
                    print(py_tx)

                    # Strip the inputs to only sigless instances
                    tx_inputs = []
                    tx_witness_del = []
                    for idx, tx_in in enumerate(py_tx.inputs):
                        if(tx_in.txid == input_txid and tx_in.txout_index == output_index):
                            tx_inputs.append(tx_in)
                        else:
                            tx_witness_del.append(idx)

                    print(f'The TXIS is: {txid}')
                    print(f'The input TXID  is: {input_txid}:{output_index}')
                    # Sort the indices based on the values from largest to smallest
                    print(f'The TX inputs are: {tx_inputs}')
                    print(f'The removed wirness idxs are: {tx_witness_del}')

                    for index in sorted(tx_witness_del, reverse=True):
                        del py_tx.witnesses[index]

                    print(f'Length of witness items is {len(py_tx.witnesses)}')

                    ''' Now lets add the inputs and outputs needed to properly bump the TX '''
                    py_tx.inputs = tx_inputs
                    # Add the outputs to the TX - Change + OP_RETURN
                    py_tx.outputs = []
                    py_tx.outputs.append(outpoint)
                    py_tx.outputs.append(change_txout)

                    print(py_tx)

                    try:
                        new_raw_tx = py_tx.serialize()
                    except Exception as E:
                        print (f"Failed to serialize raw tx\'n with exception: {E}")
                        traceback.print_exc()

                    print("Here is your RAW transaciton info")
                    print(new_raw_tx)

                    ''' add an input to fund the raw transaction '''
                    new_raw_tx = send_rpc_request("fundrawtransaction", [new_raw_tx])
                    print(new_raw_tx)

                    ''' We must sign for that pesky input for the change  '''
                    print("final signed transaction")
                    new_raw_tx = send_rpc_request("signrawtransactionwithwallet", [new_raw_tx['hex']])
                    print(new_raw_tx)

                    ''' Get the TXID so we can add it to our list of don't bump again txs '''
                    #py_tx = Transaction.from_raw(new_raw_tx)
                    #rbf_txids.append(get_txid)
                    #print(rbf_txids)

                    b_cast = send_rpc_request("sendrawtransaction", [new_raw_tx['hex']])
                    print(b_cast)

    return missing_sigs_tx

def process_txids(txid_queue):
    while True:
        txid = txid_queue.get()
        if txid is None:
            break
        check_inner_witness(txid)
        txid_queue.task_done()

def zmq_listener(txid_queue):
    context = zmq.Context()
    socket = context.socket(zmq.SUB)
    socket.setsockopt_string(zmq.SUBSCRIBE, "hashtx")
    socket.connect("tcp://127.0.0.1:28332")  # Change the address to your Bitcoin node's ZMQ address

    while True:
        msg = socket.recv_multipart()
        topic, tx_hash, _ = msg  # using _ to ignore the third part of the message
        if topic == b'hashtx':
            hex_txid = tx_hash.hex()  # convert the txid to hexadecimal
            txid_queue.put(hex_txid)

if __name__ == "__main__":
    txid_queue = queue.LifoQueue()
    zmq_thread = threading.Thread(target=zmq_listener, args=(txid_queue,))
    zmq_thread.start()

    with concurrent.futures.ThreadPoolExecutor(max_workers=44) as executor:
        futures = [executor.submit(process_txids, txid_queue) for _ in range(44)]
        concurrent.futures.wait(futures)
