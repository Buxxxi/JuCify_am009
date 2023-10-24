package lu.uni.trux.jucify.callgraph;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.javatuples.Pair;

import com.github.dakusui.combinatoradix.Permutator;

import guru.nidi.graphviz.model.Link;
import guru.nidi.graphviz.model.MutableGraph;
import guru.nidi.graphviz.model.MutableNode;
import guru.nidi.graphviz.parse.Parser;
import lu.uni.trux.jucify.ResultsAccumulator;
import lu.uni.trux.jucify.instrumentation.DummyBinaryClass;
import lu.uni.trux.jucify.utils.Constants;
import lu.uni.trux.jucify.utils.CustomPrints;
import lu.uni.trux.jucify.utils.Utils;
import soot.Body;
import soot.Local;
import soot.Modifier;
import soot.RefType;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Type;
import soot.Unit;
import soot.UnitPatchingChain;
import soot.Value;
import soot.VoidType;
import soot.javaToJimple.LocalGenerator;
import soot.jimple.AssignStmt;
import soot.jimple.IdentityStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.Jimple;
import soot.jimple.NewExpr;
import soot.jimple.Stmt;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.util.dot.DotGraph;

public class CallGraphPatcher {

	private CallGraph cg;
	private boolean raw;
	private List <SootMethod> newReachableNodes;

	public CallGraphPatcher(CallGraph cg, boolean raw) {
		this.cg = cg;
		this.raw = raw;
		this.newReachableNodes = new ArrayList<SootMethod>();
	}

	public void importBinaryCallGraph(List<Pair<String, String>> files) {
		MutableGraph g = null;
		InputStream dot = null;
		String name = null,
				nameTo = null,
				nameFrom = null,
				dotFile = null,
				entrypoints = null;

		SootMethod sm = null,
				m = null,
				from = null,
				to = null;

		Map<String, SootMethod> nodesToMethods = new HashMap<String, SootMethod>();
		CustomPrints.perror("importBinaryCallGraph files.size(): "+String.valueOf(files.size()));

		try {
			for(Pair<String, String> pair: files) {
				dotFile = pair.getValue0(); // 二进制内的cg
				entrypoints = pair.getValue1();
				dot = new FileInputStream(dotFile);
				g = new Parser().read(dot);
				if(dot == null || g == null) {
					if(!raw) {
						CustomPrints.perror("Something wrong with dot file or mutable graph");
					}
					System.exit(1);
				}


				BufferedReader is = new BufferedReader(new FileReader(entrypoints));
				List<Pair<String, SootMethod>> javaToNative = new ArrayList<Pair<String, SootMethod>>();
				Map<String, List<SootMethod>> nativeToJava = new HashMap<String, List<SootMethod>>();
				Stmt stmt = null;
				InvokeExpr ie = null;
				List<SootMethod> javaTargets = null;
				for(String line = is.readLine(); line != null; line = is.readLine()) {
					if(line.startsWith(Constants.HEADER_ENTRYPOINTS_FILE)) {
						continue;
					}
					String[] split = line.split(",");
					String clazz = split[0].trim();	// lu.uni.trux.getter_imei.MainActivity
					String method = split[1].trim();	//nativeGetImei
					String sig = split[2].trim();	// (Landroid/telephony/TelephonyManager;)Ljava/lang/String;
					String target = split[3].trim();	// Java_lu_uni_trux_getter_1imei_MainActivity_nativeGetImei
					Pair<String, String> pairNewSig = Utils.compactSigtoJimpleSig(sig);	//{"(android.telephony.TelephonyManager)", "java.lang.String"}
					String newSig = Utils.toJimpleSignature(clazz, pairNewSig.getValue1(), method, pairNewSig.getValue0()); // "<lu.uni.trux.getter_imei.MainActivity: java.lang.String nativeGetImei(android.telephony.TelephonyManager)>"
					if(!Scene.v().containsMethod(newSig)) {
						Utils.addPhantomMethod(newSig);
					}
					SootMethod nativeMethod = Scene.v().getMethod(newSig);
					for(SootClass sc: Scene.v().getApplicationClasses()) { // 遍历soot类
						for(SootMethod met: sc.getMethods()) {	// 遍历soot类中的方法
							if(met.isConcrete()) { // 该方法是否有具体的实现
								// 如果有具体实现的话，就看这个方法
								for(Unit u: met.retrieveActiveBody().getUnits()) {
									// .retrieveActiveBody()方法返回该方法的主体部分(Body)，主体部分包含实现该方法的具体的代码。
									// .getUnits()方法将这个主体部分进一步细分为多个“单元”（Units），每个单元大致对应于一条或多条Java语言的指令。这些单元可以是各种类型的指令，比如分支指令，循环指令，变量赋值指令等。
									stmt = (Stmt) u;  // stmt代表一条jimple语句
									if(stmt.containsInvokeExpr()) { // 检查stmt是否包含方法调用表达式的函数
										ie = stmt.getInvokeExpr();
										if(ie.getMethod().equals(nativeMethod)) {	// 该stmt调用了nativeMethod
											javaToNative.add(new Pair<String, SootMethod>(target, nativeMethod));	// String是native function名，nativeMethod是SootMethod的实例，是那个native method
										}
									}
								}
							}
						}
					}
					// HANDLE NATIVE TO JAVA CALLS	
					if(split.length == 10) {
						String invokeeClass = split[5].trim(); // android.telephony.TelephonyManager
						String invokeeMethod = split[6].trim(); // getDeviceId
						String invokeeSig = split[7].trim(); // ()Ljava/lang/String;
						pairNewSig = Utils.compactSigtoJimpleSig(invokeeSig); // //{"()", "java.lang.String"}
						newSig = Utils.toJimpleSignature(invokeeClass, pairNewSig.getValue1(), invokeeMethod, pairNewSig.getValue0()); // "<android.telephony.TelephonyManager: java.lang.String getDeviceId()>"
						if(!Scene.v().containsMethod(newSig)) {
							Utils.addPhantomMethod(newSig);
						}
						sm = Scene.v().getMethod(newSig); // 根据这个java method的sig，获取相应SootMethod
						javaTargets = nativeToJava.get(target);
						if(javaTargets == null) {
							javaTargets = new ArrayList<SootMethod>();
							nativeToJava.put(target, javaTargets);
						}
						javaTargets.add(sm);
					}
				}
				is.close();

				CustomPrints.perror("Java2Native: "+String.valueOf(javaToNative.size())); // javaToNative是个Pair，fist是native function字符串，second是相应的native method（sootMethod格式）
				CustomPrints.perror("Native2Java: "+String.valueOf(nativeToJava.size())); // nativeToJava的键是native function字符串，值是arraylist每个元素是该native function中调用的java method（sootMethod格式）
				// GENERATE BINARY NODES THAT ARE JAVA NATIVE CALLS AND INSTRUMENT THE BODY 把二进制函数转为jimple
				for(Pair<String, SootMethod> p: javaToNative) {
					name = p.getValue0();
					m = p.getValue1();
					if(!nodesToMethods.containsKey(name)) {
 						sm = DummyBinaryClass.v().addBinaryMethod(name,
								m.getReturnType(), m.getModifiers(),	// rettype是java.lang.String modifiers是257表示修饰符（public 的常量值为 1，private 的常量值为 2，protected 的常量值为 4， static 的常量值为 8）
								m.getParameterTypes());	// parametertypes是ArrayList["android.telephony.TelephonyManager"]
						nodesToMethods.put(name, sm); // nodesToMethods是个map，键是native function（后面也放了其他二进制函数），值是这个为native function构建的Jimple格式SootMethod
						for(SootClass sc: Scene.v().getApplicationClasses()) {
							for(SootMethod met: sc.getMethods()) { // 仍旧是遍历每个java method
								if(met.hasActiveBody()) { // 这个方法的是实现已经加载到Soot
									Body b = met.retrieveActiveBody(); // 获取该方法的活动体，通常表示为Jimple形式的语句。
									UnitPatchingChain units = b.getUnits();
									List<Unit> newUnits = null;
									Stmt point = null;
									for(Unit u: units) {
										stmt = (Stmt) u;
										if(stmt.containsInvokeExpr()) {
											ie = stmt.getInvokeExpr();
											if(ie.getMethod().equals(m)) { // 找到所有调用了Native Method的java method(met) onCreate
												Pair<Local, Pair<List<Unit>, Stmt>> locNewUnits = DummyBinaryClass.v().checkDummyBinaryClassLocalExistence(b, stmt);
												Local dummyBinaryClassLocal = locNewUnits.getValue0();
												Pair<List<Unit>, Stmt> newUnitsPoint = locNewUnits.getValue1();
												if(newUnitsPoint != null) {
													newUnits = newUnitsPoint.getValue0();
													point = newUnitsPoint.getValue1();
												}
												if(stmt instanceof AssignStmt) {
													AssignStmt as = (AssignStmt) stmt;
													if(sm.isStatic()) {
														as.setRightOp(Jimple.v().newStaticInvokeExpr(sm.makeRef(), ie.getArgs()));
													}else if(sm.isConstructor()){
														as.setRightOp(Jimple.v().newSpecialInvokeExpr(dummyBinaryClassLocal, sm.makeRef(), ie.getArgs()));
													}else {
														as.setRightOp(Jimple.v().newVirtualInvokeExpr(dummyBinaryClassLocal, sm.makeRef(), ie.getArgs()));
													}
												}else if(stmt instanceof InvokeStmt) {
													InvokeStmt ivs = (InvokeStmt) stmt;
													if(sm.isStatic()) {
														ivs.setInvokeExpr(Jimple.v().newStaticInvokeExpr(sm.makeRef(), ie.getArgs()));
													}else if(sm.isConstructor()){
														ivs.setInvokeExpr(Jimple.v().newSpecialInvokeExpr(dummyBinaryClassLocal, sm.makeRef(), ie.getArgs()));
													}else {
														ivs.setInvokeExpr(Jimple.v().newVirtualInvokeExpr(dummyBinaryClassLocal, sm.makeRef(), ie.getArgs()));
													}
												}
											}
											// Modify native call to newly generated call + add edge to call-graph
											if(ie.getMethod().equals(m)) {
												ie.setMethodRef(sm.makeRef());
												this.cg.addEdge(new Edge(met, stmt, sm));
												this.newReachableNodes.add(sm);
												ResultsAccumulator.v().incrementNumberNewJavaToNativeCallGraphEdges();
												if(!raw) {	// met是调用native method的java method（onCreate）,sm是被调用的native function(<DummyBinaryClass: java.lang.String Java_lu_uni_trux_getter_1imei_MainActivity_nativeGetImei(android.telephony.TelephonyManager)>)
													CustomPrints.pinfo(String.format("Adding java-to-native Edge from %s to %s", met, sm));
												}
											}
										}
									}
									if(newUnits != null && point != null) {
										units.insertBefore(newUnits, point);
										b.validate();
									}
								}
							}
						}
						// Handle Native to Java
						javaTargets = nativeToJava.get(name);
						Unit lastAdded = null,
								insertPoint = null;
						if(javaTargets != null && !javaTargets.isEmpty()) {
							for(SootMethod met: javaTargets) {
								Type ret = met.getReturnType();
								Body b = sm.retrieveActiveBody();
								Local local = null;
								LocalGenerator lg = new LocalGenerator(b);
								local = DummyBinaryClass.v().getOrGenerateLocal(b, this.getfirstAfterIdenditiesUnits(b), met.getDeclaringClass().getType());

								int paramLength = met.getParameterCount();
								List<Value> potentialParameters = new ArrayList<Value>();

								boolean found;
								for(Type t: met.getParameterTypes()) {
									found = false;
									for(Local l: b.getLocals()) {
										if(l.getType().equals(t)) {
											if(!potentialParameters.contains(l)) {
												potentialParameters.add(l);
												found = true;
											}
										}
									}
									if(!found) {
										potentialParameters.add(DummyBinaryClass.v().generateLocalAndNewStmt(b, this.getfirstAfterIdenditiesUnits(b), t));
									}
								}

								boolean isGoodCombi = true;
								Permutator<Value> permutator = new Permutator<Value>(potentialParameters, paramLength);
								for (List<Value> parameters : permutator) {
									isGoodCombi = true;
									for(int i = 0 ; i < paramLength ; i++) {
										if(!parameters.get(i).getType().equals(met.getParameterTypes().get(i))) {
											isGoodCombi = false;
											break;
										}
									}
									// OK NOW ADD OPAQUE PREDICATE
									if(isGoodCombi) {
										if(met.isConstructor()) {
											ie = Jimple.v().newSpecialInvokeExpr(local, met.makeRef(), parameters);
										}else if(met.isStatic()) {
											ie = Jimple.v().newStaticInvokeExpr(met.makeRef(), parameters);
										}else {
											ie = Jimple.v().newVirtualInvokeExpr(local, met.makeRef(), parameters);
										}
										Stmt newStmt = null;
										if(ret.equals(VoidType.v())) {
											newStmt = Jimple.v().newInvokeStmt(ie);
										}else {
											local = lg.generateLocal(met.getReturnType());
											newStmt = Jimple.v().newAssignStmt(local, ie);
										}
										if(newStmt != null) {
											if(lastAdded == null) {
												insertPoint = this.getfirstAfterIdenditiesUnitsAfterInit(b);
												b.getUnits().insertBefore(newStmt, insertPoint);
											}else {
												insertPoint = lastAdded;
												b.getUnits().insertAfter(newStmt, insertPoint);
											}
											lastAdded = newStmt;
											if(permutator.size() > 1) {
												DummyBinaryClass.v().addOpaquePredicate(b, b.getUnits().getSuccOf(newStmt), newStmt);
											}
										}
										Edge e = new Edge(sm, newStmt, met);
										this.cg.addEdge(e);
										this.newReachableNodes.add(met);
										ResultsAccumulator.v().incrementNumberNewNativeToJavaCallGraphEdges();
										if(!raw) { // sm是<DummyBinaryClass: java.lang.String Java_lu_uni_trux_getter_1imei_MainActivity_nativeGetImei(android.telephony.TelephonyManager)>， met是<android.telephony.TelephonyManager: java.lang.String getDeviceId()>
											CustomPrints.pinfo(String.format("Adding native-to-java Edge from %s to %s", sm, met));
										}
									}
								}

								if(!sm.getReturnType().equals(VoidType.v())) {
									// FIX MULTIPLE RETURN OF SAME TYPE (OPAQUE PREDICATE)
									final Local retLoc = local;
									DummyBinaryClass.v().addOpaquePredicateForReturn(b, b.getUnits().getLast(), Jimple.v().newReturnStmt(retLoc));
								}
								
								
								b.validate();
							}
						}
					}
				}
				// 上面为止完成了native function的SootMethod的创建和并入（连接调用native method的java method到这个模拟的sootmethod的边，连接在native function里调用的java method）
				// GENERATE BINARY NODES INTO SOOT CALL GRAPH 这里生成所有二进制cg（.so.callgraph文件）的二进制函数的sootmethod
				for(MutableNode node: g.nodes()) {	// 遍历二进制cg（.so.callgraph文件）的节点
					name = Utils.removeNodePrefix(node.name().toString());
					if(!nodesToMethods.containsKey(name)) {
						sm = DummyBinaryClass.v().addBinaryMethod(name, VoidType.v(), Modifier.PUBLIC, new ArrayList<>());
						nodesToMethods.put(name, sm); // 为每个被调用到的二进制函数创建一个空的SootMethod
					}
					System.out.println("hello!!");
					System.out.println(nodesToMethods.get(name).getSignature());
				}



				// ADD EDGE FROM INITIAL BINARY CALL-GRAPH
				for(Link l: g.edges()) {
					nameFrom = Utils.removeNodePrefix(l.from().name().toString());
					nameTo = Utils.removeNodePrefix(l.to().name().toString());
					from = nodesToMethods.get(nameFrom);
					to = nodesToMethods.get(nameTo);
					stmt = (Stmt) Utils.addMethodCall(from, to);
					if(stmt != null) {
						Edge e = new Edge(from, stmt, to);
						this.cg.addEdge(e);
						this.newReachableNodes.add(to);
					}
				}
			}

		} catch (IOException e) {
			if(!raw) {
				CustomPrints.perror(e.getMessage());
			}
			System.exit(1);
		}
	}

	private Unit getfirstAfterIdenditiesUnits(Body b) {
		UnitPatchingChain units = b.getUnits();
		Unit u = null;
		Iterator<Unit> it = units.iterator();
		u = it.next();
		while(u instanceof IdentityStmt) {
			u = it.next();
		}
		return u;
	}

	private Unit getfirstAfterIdenditiesUnitsAfterInit(Body b) {
		UnitPatchingChain units = b.getUnits();
		Unit u = null;
		Iterator<Unit> it = units.iterator();
		u = it.next();
		while(u instanceof IdentityStmt) {
			u = it.next();
		}
		boolean found = false;
		while(!found) {
			if(u instanceof AssignStmt) {
				AssignStmt as = (AssignStmt) u;
				Value rop = as.getRightOp();
				if(rop instanceof NewExpr) {
					u = it.next();
					if(u instanceof InvokeStmt) {
						InvokeStmt is = (InvokeStmt) u;
						if(is.getInvokeExpr().getMethod().getSubSignature().equals(Constants.INIT_METHOD_SUBSIG)) {
							u = it.next();
							continue;
						}
					}
				}
			}
			found = true;
		}
		return u;
	}

	public void dotifyCallGraph(String destination) {
		DotGraph dg = new DotGraph(Constants.GRAPH_NAME);
		Iterator<Edge> it = this.cg.iterator();
		Edge next = null;
		while(it.hasNext()) {
			next = it.next();
			dg.drawEdge(next.src().getName(), next.tgt().getName());
		}
		dg.plot(destination);
	}

	public List<SootMethod> getNewReachableNodes() {
		return newReachableNodes;
	}

	public void setNewReachableNodes(List<SootMethod> newReachableNodes) {
		this.newReachableNodes = newReachableNodes;
	}
	
	public List<SootMethod> getNewReachableNodesNative() {
		return getNewReachableNodes(true);
	}
	
	public List<SootMethod> getNewReachableNodesJava() {
		return getNewReachableNodes(false);
	}
	
	private List<SootMethod> getNewReachableNodes(boolean b) {
		List<SootMethod> s = new ArrayList<SootMethod>();
		for(SootMethod sm: this.newReachableNodes) {
			if(sm.getDeclaringClass().getType().equals(RefType.v(Constants.DUMMY_BINARY_CLASS)) && b) {
				if(!s.contains(sm)) {
					s.add(sm);
				}
			}else if (!sm.getDeclaringClass().getType().equals(RefType.v(Constants.DUMMY_BINARY_CLASS)) && !b){
				if(!s.contains(sm) && !Utils.wasMethodPreviouslyReachableInCallGraph(cg, sm)) {
					s.add(sm);
				}
			}
		}
		return s;
	}
}
