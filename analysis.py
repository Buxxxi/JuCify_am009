import csv
import pygraphviz as pgv
import argparse
import os
import shutil
import pymongo
from networkx.drawing.nx_agraph import read_dot
import networkx as nx
import json
import re


compact_types_to_jimple_types = None
def get_compact_types_to_jimple_types(key):
    global compact_types_to_jimple_types
    if compact_types_to_jimple_types is None:
        compact_types_to_jimple_types = {}
        compact_types_to_jimple_types["V"] = "void"
        compact_types_to_jimple_types["Z"] = "boolean"
        compact_types_to_jimple_types["B"] = "byte"
        compact_types_to_jimple_types["C"] = "char"
        compact_types_to_jimple_types["S"] = "short"
        compact_types_to_jimple_types["I"] = "int"
        compact_types_to_jimple_types["J"] = "long"
        compact_types_to_jimple_types["F"] = "float"
        compact_types_to_jimple_types["D"] = "double"
    if key.startswith("L"):
        return key[1:-1].replace("/", ".")
    elif key.startswith("["):
        if ";" in key:
            return "%s[]" % key[2:-1].replace("/", ".")
        else:
            return "%s[]" % key[1:-1].replace("/", ".")
    return compact_types_to_jimple_types.get(key)


def compact_sigto_jimple_sig(sig):
    sig = sig.strip()
    split = sig.split(")")
    ret = split[1]
    splitSplit = split[0].split("(")
    params = None
    sb = ["("]
    if len(splitSplit) != 0:
        params = splitSplit[1]
        paramsList = []
        i = 0
        while(i < len(params)):
            c = params[i]
            if c == ' ':
                i += 1
                continue
            if c == 'L':
                tmpStr = []
                while c != ';':
                    c = params[i]
                    tmpStr.append(c)
                    i += 1
                paramsList.append(get_compact_types_to_jimple_types("".join(tmpStr)))
            elif c == '[':
                tmpStr = []
                tmpStr.append(params[i + 1])
                i += 1
                paramsList.append("%s[]" % ("".join(tmpStr)))
            else:
                paramsList.append(get_compact_types_to_jimple_types(c))
                i += 1
        sb.append(",".join(paramsList))
    sb.append(")")
    ret = get_compact_types_to_jimple_types(ret)
    return ("".join(sb), ret)


def to_jimple_signature(clazz, ret, method, params):
    return '<{}: {} {}{}>'.format(clazz, ret, method, params)


def main(args):
    apk_path = args.apk
    package_name = args.package
    # 先把输入的apk存入
    apk_dir = os.path.abspath(os.path.join(os.path.abspath(__file__),'..','apkDir'))
    if not os.path.exists(apk_dir):
        os.makedirs(apk_dir)
    apk_name = os.path.basename(apk_path)   # 带后缀的apk文件名
    apk_base_name = os.path.basename(apk_path)  # 不带后缀的apk文件名
    if apk_base_name.endswith('.apk'):
        apk_base_name = apk_base_name[:-4]
    analysis_result_dir = os.path.join(apk_dir, apk_base_name)
    if not os.path.exists(analysis_result_dir):
        os.makedirs(analysis_result_dir)
    shutil.copy(apk_path, os.path.join(analysis_result_dir, apk_name))
    apk_path =  os.path.join(analysis_result_dir, apk_name)

    # 运行runTool脚本
    runTool_script_path = os.path.abspath(os.path.join(os.path.abspath(__file__),'..','runTool.sh'))
    platforms_dir = os.path.abspath(os.path.join(os.path.abspath(__file__),'..','..','platforms'))
    print(runTool_script_path)
    print(platforms_dir)
    print("开始运行runTool.sh")
    cmd_list = [runTool_script_path, '-p', platforms_dir, '-f', apk_path, '-t','-e','b']
    os.system(' '.join(cmd_list))
    print("结束运行runTool.sh")

    # 下面开始把结果进行整理
    print("开始整理结果")
    node_to_jimple_sig_dict = dict()
    node_list = []
    edge_list = []
    native_discloser_result_dir = os.path.join(analysis_result_dir, apk_base_name+'_result')
    native_discloser_result_list = os.listdir(native_discloser_result_dir)
    for native_discloser_result in native_discloser_result_list:
        if native_discloser_result.endswith('.so.result'):
            native_discloser_result_path = os.path.join(native_discloser_result_dir, native_discloser_result)
            with open(native_discloser_result_path, 'r') as f:
                reader = csv.reader(f)
                for row in reader:
                    if row[0]=='invoker_cls':
                        continue
                    # print(row)
                    clazz = row[0].strip()
                    method = row[1].strip()
                    sig = row[2].strip()
                    target = row[3].strip()
                    # print(target)
                    pair_new_sig = compact_sigto_jimple_sig(sig)
                    new_sig = to_jimple_signature(clazz, pair_new_sig[1], method, pair_new_sig[0])
                    target_new_sig = to_jimple_signature('DummyBinaryClass', pair_new_sig[1], target, pair_new_sig[0])
                    if not new_sig in node_list:
                        node_list.append(new_sig)
                    if not target_new_sig in node_list:
                        node_list.append(target_new_sig)
                        node_to_jimple_sig_dict[target] = target_new_sig
                    edge_list.append((new_sig, target_new_sig))

    # 创建有向图（设置为True表示是有向图，如果不设置或设置为False，则表示是无向图）
    G = pgv.AGraph(directed=True)
    apk_unzip_dir = os.path.join(analysis_result_dir, apk_base_name)
    apk_unzip_dir_list = os.listdir(apk_unzip_dir)
    for unzip_file in apk_unzip_dir_list:
        if unzip_file.endswith('.so.callgraph'):
            so_callgraph_path = os.path.join(apk_unzip_dir, unzip_file)
            # 读取文件
            G = pgv.AGraph(filename=so_callgraph_path)
            # 迭代遍历节点和边
            for node in G.nodes():
                if node.startswith('Node_'):
                    node = node[5:]
                # print(node)
                if node in node_to_jimple_sig_dict:
                    continue
                node_new_sig = to_jimple_signature('DummyBinaryClass', 'void', node, "()")
                node_to_jimple_sig_dict[node] = node_new_sig
                node_list.append(node_new_sig)
            for edge in G.edges():
                from_node = edge[0]
                to_node = edge[1]
                if from_node.startswith('Node_'):
                    from_node = from_node[5:]
                if to_node.startswith('Node_'):
                    to_node = to_node[5:]
                edge_list.append((node_to_jimple_sig_dict[from_node], node_to_jimple_sig_dict[to_node]))
    print(node_list)
    print(edge_list)

    # 有了节点信息之后，写数据库 写文件
    print("开始写数据库")
    myclient = pymongo.MongoClient("mongodb://10.181.7.224:27018/")
    # 判断是否已存在当前apk的数据库
    dblist = myclient.list_database_names()
    if not package_name.replace('.', '_') in dblist:
        apk_database = myclient[package_name.replace('.','_')]
        cf_nodes_table = apk_database["cf_nodes"]
        cf_edges_table = apk_database["control_flow"]
        df_nodes_table = apk_database["df_nodes"]
        df_edges_table = apk_database["data_flow"]
        cf_nodes_id = 0    # 下一个待插入的node的id
        cf_edges_id = 0
        df_nodes_id = 0
        df_edges_id = 0
    else: # 当前apk的数据库已存在
        apk_database = myclient[package_name.replace('.','_')]
        cf_nodes_table = apk_database["cf_nodes"]
        cf_edges_table = apk_database["control_flow"]
        df_nodes_table = apk_database["df_nodes"]
        df_edges_table = apk_database["data_flow"]
        cf_nodes_id = cf_nodes_table.count_documents({})    # 下一个待插入的node的id
        cf_edges_id = cf_edges_table.count_documents({})    # 下一个待插入的edge的id
        df_nodes_id = df_nodes_table.count_documents({})
        df_edges_id = df_edges_table.count_documents({})

    node2id_dict = {}
    for node in node_list:
        # 判断当前节点是否已经存在在数据库中
        record_node = cf_nodes_table.find_one({"name":node})
        if record_node:
            node2id_dict[node] = int(record_node["id"])
            continue
        # 不存在 则插入
        node_dict = {"name":node, "id":cf_nodes_id, "in_degree":0}
        node2id_dict[node] = cf_nodes_id
        cf_nodes_table.insert_one(node_dict)
        cf_nodes_id+=1
    for edge in edge_list:
        source_id = node2id_dict[edge[0]]
        target_id = node2id_dict[edge[1]]
        record_edge = cf_edges_table.find_one({"source":str(source_id), "target":str(target_id)})
        if record_edge:
            in_degree = record_edge["in_degree"]
            cf_edges_table.update_one({"source":str(source_id), "target":str(target_id)}, {"$set":{"call_sum":in_degree+1}})
        else:
            # 不存在 则插入
            edge_dict = {"id":str(cf_edges_id), "source":str(source_id), "target":str(target_id), "call_sum":1}
            cf_edges_table.insert_one(edge_dict)
            cf_edges_id+=1
    
    # 下面是控制流的敏感场景
    print("开始敏感场景分析")
    # 加密函数
    encrypt_json ={}
    encrypt_nodename2id_dict = {}
    encrypt_node_id = 0
    encrypt_node_list = []
    encrypt_edge_list = []
    encrypt_added_edge_set = set()
    for unzip_file in apk_unzip_dir_list:
        if unzip_file.endswith('.so.callgraph'):
            lib_file_name = unzip_file.split('.so.callgraph')[0]
            so_callgraph_path = os.path.join(apk_unzip_dir, unzip_file)
            graph = read_dot(so_callgraph_path)
            encrypt_keywords = ["encrypt", "AES", "RSA", "rsa", "md5", "MD5"]
            # readwrite_keywords = ["fwrite", "fread", "__android_log_write"]
            # 找到根节点
            root_nodes = [n for n,d in graph.in_degree() if d==0]
            # print(rf'root_nodes:{root_nodes}')
            encrypt_leaf_nodes = [n for n,d in graph.out_degree() if d==0 and any(keyword in n.lower() for keyword in encrypt_keywords)]
            # readwrite_leaf_nodes = [n for n,d in graph.out_degree() if d==0 and any(keyword in n.lower() for keyword in readwrite_keywords)]
            
            encrypt_path_list = []
            for root in root_nodes:
                for leaf in encrypt_leaf_nodes:
                    for path in nx.all_simple_paths(graph, source=root, target=leaf):
                        encrypt_path_list.append(path)
            for encrypt_path in encrypt_path_list:
                for encrypt_node in encrypt_path:
                    encrypt_nodename2id_dict[encrypt_node] = encrypt_node_id
                    is_jni_flag = False
                    if encrypt_node in root_nodes:
                        is_jni_flag = True
                    info_dict= {"name":encrypt_node, "file":lib_file_name, "is_JNI":is_jni_flag, "id":encrypt_node_id}
                    encrypt_node_id+=1
                    encrypt_node_list.append(info_dict)
                
                for i in range(len(encrypt_path)-1):
                    src_id = encrypt_nodename2id_dict[encrypt_path[i]]
                    dest_id = encrypt_nodename2id_dict[encrypt_path[i+1]]
                    if (src_id, dest_id) not in encrypt_added_edge_set:
                        encrypt_added_edge_set.add((src_id, dest_id))
                        encrypt_edge_list.append({"src_id":src_id, "dest_id":dest_id})
    encrypt_json["nodes"] = encrypt_node_list
    encrypt_json["edges"] = encrypt_edge_list
    # 写入文件
    encrypt_output_dir = os.path.join(analysis_result_dir, 'encrypt')
    if not os.path.exists(encrypt_output_dir):
        os.makedirs(encrypt_output_dir)
    output_path = os.path.join(encrypt_output_dir, apk_base_name+'.json')
    with open(output_path, 'w') as f:
        json.dump(encrypt_json, f, indent=4)

    # 文件读写
    readwrite_json ={}
    readwrite_nodename2id_dict = {}
    readwrite_node_id = 0
    readwrite_node_list = []
    readwrite_edge_list = []
    readwrite_added_edge_set = set()
    for unzip_file in apk_unzip_dir_list:
        if unzip_file.endswith('.so.callgraph'):
            lib_file_name = unzip_file.split('.so.callgraph')[0]
            so_callgraph_path = os.path.join(apk_unzip_dir, unzip_file)
            graph = read_dot(so_callgraph_path)
            readwrite_keywords = ["fwrite", "fread", "__android_log_write"]
            # 找到根节点
            root_nodes = [n for n,d in graph.in_degree() if d==0]
            # print(rf'root_nodes:{root_nodes}')
            readwrite_leaf_nodes = [n for n,d in graph.out_degree() if d==0 and any(keyword in n.lower() for keyword in readwrite_keywords)]
            
            readwrite_path_list = []
            for root in root_nodes:
                for leaf in readwrite_leaf_nodes:
                    for path in nx.all_simple_paths(graph, source=root, target=leaf):
                        readwrite_path_list.append(path)
            for readwrite_path in readwrite_path_list:
                for readwrite_node in readwrite_path:
                    readwrite_nodename2id_dict[readwrite_node] = readwrite_node_id
                    is_jni_flag = False
                    if readwrite_node in root_nodes:
                        is_jni_flag = True
                    info_dict= {"name":readwrite_node, "file":lib_file_name, "is_JNI":is_jni_flag, "id":readwrite_node_id}
                    readwrite_node_id+=1
                    readwrite_node_list.append(info_dict)
                
                for i in range(len(readwrite_path)-1):
                    src_id = readwrite_nodename2id_dict[readwrite_path[i]]
                    dest_id = readwrite_nodename2id_dict[readwrite_path[i+1]]
                    if (src_id, dest_id) not in readwrite_added_edge_set:
                        readwrite_added_edge_set.add((src_id, dest_id))
                        readwrite_edge_list.append({"src_id":src_id, "dest_id":dest_id})
    readwrite_json["nodes"] = readwrite_node_list
    readwrite_json["edges"] = readwrite_edge_list
    # 写入文件
    readwrite_output_dir = os.path.join(analysis_result_dir, 'readwrite')
    if not os.path.exists(readwrite_output_dir):
        os.makedirs(readwrite_output_dir)
    output_path = os.path.join(readwrite_output_dir, apk_base_name+'.json')
    with open(output_path, 'w') as f:
        json.dump(readwrite_json, f, indent=4)
    
    # 下面将数据流结果整理，待写进数据库
    native_log_path = os.path.join(analysis_result_dir, apk_name+'.flow.log')
    all_flow_list = []
    collecting = False
    one_flow_list = []
    if not os.path.exists(native_log_path):
        print(rf"{native_log_path}不存在")
    with open(native_log_path, 'r') as f:
        for line in f:
            line = line.strip()
            if 'Found path through native code' in line:
                if one_flow_list:
                    all_flow_list.append(one_flow_list)
                    one_flow_list = []
                collecting = True  # Start collecting lines
                # section.append(line)  # Also include the start line
            elif 'Taint Analysis performed' in line and collecting:
                collecting = False  # Stop collecting lines
                # section.append(line)  # Also include the end line
                all_flow_list.append(one_flow_list)  # Add this section to our results
                one_flow_list = []  # Reset section
            elif collecting:
                one_flow_list.append(line)  # Collect line
    ready_to_mongodb_list = []
    for one_flow_list in all_flow_list:
        for line in one_flow_list[2:-1]:
            match = re.search(r'(.*?)( => in method: <)(.*?)(:)(.*?)(>)', line)
            if match:
                stmt = match.group(1).strip()
                class_name = match.group(3).strip()
                method_name = match.group(5).strip()
                ready_to_mongodb_list.append([stmt, class_name, method_name])
    print(ready_to_mongodb_list)
    # 下面开始写数据库
    node2id_dict = {}
    for i, data_flow in enumerate(ready_to_mongodb_list):
        # 看当前这条数据流在不在数据库中
        _stmt, _clazz, _method = data_flow
        record_node = df_nodes_table.find_one({"stmt":_stmt,"method":_method,"class":_clazz})
        if record_node:
            node2id_dict[_stmt+"@@@"+_clazz+"@@@"+_method] = int(record_node["id"])
            continue
        # 这是一个新的数据流节点
        tmp_name = '$'
        if '=' in _stmt:
            tmp_name = _stmt.split('=')[0].strip()
        _tw = "Native"
        if i==0:
            _tw = "Source"
        elif i== len(ready_to_mongodb_list) - 1:
            _tw = "Sink"
        node_dict = {"id":df_nodes_id, "type":_clazz, "name":tmp_name, "TW":_tw, "stmt":_stmt,"method":_method,"class":_clazz}
        node2id_dict[_stmt+"@@@"+_clazz+"@@@"+_method] = df_nodes_id
        df_nodes_table.insert_one(node_dict)
        df_nodes_id+=1
    # 下面加边
    for i in range(len(ready_to_mongodb_list)-1):
        _stmt_src, _clazz_src, _method_src = ready_to_mongodb_list[i]
        _stmt_dest, _clazz_dest, _method_dest = ready_to_mongodb_list[i+1]
        src_id = node2id_dict[_stmt_src+"@@@"+_clazz_src+"@@@"+_method_src]
        dest_id = node2id_dict[_stmt_dest+"@@@"+_clazz_dest+"@@@"+_method_dest]
        record_edge = df_edges_table.find_one({"source":str(source_id), "target":str(target_id)})
        if record_edge:
            continue
        else:
            # 不存在 则插入
            edge_dict = {"source":str(src_id), "target":str(dest_id)}
            df_edges_table.insert_one(edge_dict)

    

if __name__=='__main__':
    parser = argparse.ArgumentParser(description='DroidReach APK analyzer')
    parser.add_argument('--package', help='apk package_name', required=True)
    parser.add_argument("apk", help="The binary to analyze")
    args = parser.parse_args()
    main(args)

