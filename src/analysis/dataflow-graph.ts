/**
 * Dataflow Graph Construction
 *
 * Builds a dataflow graph from TypeScript AST by tracking:
 * - Variable declarations and assignments
 * - Property access (read/write)
 * - Function calls and arguments
 * - Template literals
 * - Object construction
 *
 * Phase 3.1: Dataflow Implementation
 */

import * as ts from 'typescript';
import { DataFlowGraph, DataFlowNode, DataFlowEdge, NodeType, EdgeType } from './dataflow-types.js';

/**
 * Build dataflow graph from TypeScript source code
 */
export function buildDataFlowGraph(sourceFile: ts.SourceFile): DataFlowGraph {
  const builder = new DataFlowGraphBuilder();
  builder.visitNode(sourceFile);
  return builder.getGraph();
}

/**
 * Internal graph builder with visitor pattern
 */
class DataFlowGraphBuilder {
  private nodes: DataFlowNode[] = [];
  private edges: DataFlowEdge[] = [];
  private nodeIdCounter = 0;
  private variableMap = new Map<string, string>(); // variable name → node ID
  private sourceNodeIds: string[] = [];
  private sinkNodeIds: string[] = [];

  /**
   * Get the constructed graph
   */
  getGraph(): DataFlowGraph {
    return {
      nodes: this.nodes,
      edges: this.edges,
      sourceNodeIds: this.sourceNodeIds,
      sinkNodeIds: this.sinkNodeIds,
    };
  }

  /**
   * Create a unique node ID
   */
  private createNodeId(prefix: string, line: number, column: number): string {
    return `${prefix}_${line}_${column}_${this.nodeIdCounter++}`;
  }

  /**
   * Add a node to the graph
   */
  private addNode(
    type: NodeType,
    identifier: string | undefined,
    line: number,
    column: number,
    metadata?: Record<string, any>
  ): string {
    const id = this.createNodeId(type, line, column);
    this.nodes.push({
      id,
      type,
      identifier,
      line,
      column,
      metadata,
    });
    return id;
  }

  /**
   * Add an edge to the graph
   */
  private addEdge(from: string, to: string, type: EdgeType, label?: string): void {
    this.edges.push({ from, to, type, label });
  }

  /**
   * Visit AST node and build graph
   */
  visitNode(node: ts.Node): void {
    // Variable declarations: const a = b
    if (ts.isVariableDeclaration(node)) {
      this.visitVariableDeclaration(node);
    }

    // Binary expressions: a = b
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      this.visitAssignment(node);
    }

    // Property access: obj.prop
    if (ts.isPropertyAccessExpression(node)) {
      this.visitPropertyAccess(node);
    }

    // Call expressions: func(arg)
    if (ts.isCallExpression(node)) {
      this.visitCallExpression(node);
    }

    // Template literals: `${expr}`
    if (ts.isTemplateExpression(node)) {
      this.visitTemplateExpression(node);
    }

    // Object literals: { key: value }
    if (ts.isObjectLiteralExpression(node)) {
      this.visitObjectLiteral(node);
    }

    // Recurse into children
    ts.forEachChild(node, (child) => this.visitNode(child));
  }

  /**
   * Handle variable declaration: const a = b
   */
  private visitVariableDeclaration(node: ts.VariableDeclaration): void {
    const varName = node.name.getText();
    const line = this.getLine(node);
    const column = this.getColumn(node);

    // Create node for the variable
    const varNodeId = this.addNode('variable', varName, line, column);
    this.variableMap.set(varName, varNodeId);

    // If initializer exists, create dataflow edge
    if (node.initializer) {
      this.handleInitializer(varNodeId, node.initializer);
    }
  }

  /**
   * Handle assignment: a = b
   */
  private visitAssignment(node: ts.BinaryExpression): void {
    const left = node.left;
    const right = node.right;

    // Get or create node for left side
    let leftNodeId: string | undefined;

    if (ts.isIdentifier(left)) {
      const varName = left.getText();
      leftNodeId = this.variableMap.get(varName);
      if (!leftNodeId) {
        leftNodeId = this.addNode('variable', varName, this.getLine(left), this.getColumn(left));
        this.variableMap.set(varName, leftNodeId);
      }
    } else if (ts.isPropertyAccessExpression(left)) {
      // Handle property assignment: obj.prop = value
      leftNodeId = this.addNode(
        'property',
        left.getText(),
        this.getLine(left),
        this.getColumn(left)
      );
    }

    if (leftNodeId) {
      this.handleInitializer(leftNodeId, right);
    }
  }

  /**
   * Handle property access: obj.prop
   */
  private visitPropertyAccess(node: ts.PropertyAccessExpression): void {
    const propName = node.getText();
    const line = this.getLine(node);
    const column = this.getColumn(node);

    // Check for process.env (taint source)
    if (propName.startsWith('process.env.') || propName.includes('process.env[')) {
      const sourceNodeId = this.addNode('source', propName, line, column, {
        sourceType: 'env-var',
        envVarName: propName.replace(/^process\.env\./, '').replace(/process\.env\[['"](.+)['"]\]/, '$1'),
      });
      this.sourceNodeIds.push(sourceNodeId);
    }
  }

  /**
   * Handle call expression: func(arg1, arg2)
   */
  private visitCallExpression(node: ts.CallExpression): void {
    const funcName = this.getFunctionName(node);
    const line = this.getLine(node);
    const column = this.getColumn(node);

    // Check if this is a taint sink
    if (this.isSinkFunction(funcName)) {
      const sinkNodeId = this.addNode('sink', funcName, line, column, {
        sinkType: this.getSinkType(funcName),
        functionName: funcName,
      });
      this.sinkNodeIds.push(sinkNodeId);

      // Create edges from arguments to sink
      node.arguments.forEach((arg, index) => {
        const argNodeId = this.getOrCreateNodeForExpression(arg);
        if (argNodeId) {
          this.addEdge(argNodeId, sinkNodeId, 'function-call', `arg${index}`);
        }
      });
    }
  }

  /**
   * Handle template expression: `${expr}`
   */
  private visitTemplateExpression(node: ts.TemplateExpression): void {
    const line = this.getLine(node);
    const column = this.getColumn(node);
    const templateNodeId = this.addNode('operation', 'template-literal', line, column);

    // Create edges from each template span expression
    node.templateSpans.forEach((span) => {
      const exprNodeId = this.getOrCreateNodeForExpression(span.expression);
      if (exprNodeId) {
        this.addEdge(exprNodeId, templateNodeId, 'template-literal');
      }
    });
  }

  /**
   * Handle object literal: { key: value }
   * Note: We don't create the object node here, as it's created in getOrCreateNodeForExpression
   * This method just ensures we visit the properties
   */
  private visitObjectLiteral(_node: ts.ObjectLiteralExpression): void {
    // Properties will be visited through recursive forEachChild
  }

  /**
   * Handle initializer expression (right side of assignment)
   */
  private handleInitializer(targetNodeId: string, initializer: ts.Expression): void {
    const sourceNodeId = this.getOrCreateNodeForExpression(initializer);
    if (sourceNodeId) {
      this.addEdge(sourceNodeId, targetNodeId, 'assignment');
    }
  }

  /**
   * Get or create node for an expression
   */
  private getOrCreateNodeForExpression(expr: ts.Expression): string | undefined {
    // Identifier: variable reference
    if (ts.isIdentifier(expr)) {
      const varName = expr.getText();
      let nodeId = this.variableMap.get(varName);
      if (!nodeId) {
        nodeId = this.addNode('variable', varName, this.getLine(expr), this.getColumn(expr));
        this.variableMap.set(varName, nodeId);
      }
      return nodeId;
    }

    // Property access: process.env.X, obj.prop
    if (ts.isPropertyAccessExpression(expr)) {
      const propName = expr.getText();
      const line = this.getLine(expr);
      const column = this.getColumn(expr);

      // Check for process.env (taint source)
      if (propName.startsWith('process.env.') || propName.includes('process.env[')) {
        const sourceNodeId = this.addNode('source', propName, line, column, {
          sourceType: 'env-var',
          envVarName: propName.replace(/^process\.env\./, '').replace(/process\.env\[['"](.+)['"]\]/, '$1'),
        });
        this.sourceNodeIds.push(sourceNodeId);
        return sourceNodeId;
      }

      // Property read: obj.prop (create edge from obj to prop)
      const propNodeId = this.addNode('property', propName, line, column);

      // Get the object being accessed
      const objExpr = expr.expression;
      if (ts.isIdentifier(objExpr)) {
        const objName = objExpr.getText();
        const objNodeId = this.variableMap.get(objName);
        if (objNodeId) {
          this.addEdge(objNodeId, propNodeId, 'property-read', expr.name.getText());
        }
      }

      return propNodeId;
    }

    // Template literal
    if (ts.isTemplateExpression(expr) || ts.isNoSubstitutionTemplateLiteral(expr)) {
      const line = this.getLine(expr);
      const column = this.getColumn(expr);
      return this.addNode('operation', 'template-literal', line, column);
    }

    // Object literal
    if (ts.isObjectLiteralExpression(expr)) {
      const line = this.getLine(expr);
      const column = this.getColumn(expr);
      const objNodeId = this.addNode('operation', 'object-literal', line, column);

      // Create edges from property values to object
      expr.properties.forEach((prop) => {
        if (ts.isPropertyAssignment(prop)) {
          const valueNodeId = this.getOrCreateNodeForExpression(prop.initializer);
          if (valueNodeId) {
            const propName = prop.name.getText();
            this.addEdge(valueNodeId, objNodeId, 'object-construction', propName);
          }
        }
      });

      return objNodeId;
    }

    // Call expression
    if (ts.isCallExpression(expr)) {
      const funcName = this.getFunctionName(expr);
      const line = this.getLine(expr);
      const column = this.getColumn(expr);

      // If it's a source (e.g., fetch response), create source node
      if (funcName === 'fetch' || funcName.includes('.json') || funcName.includes('.text')) {
        const sourceNodeId = this.addNode('source', funcName, line, column, {
          sourceType: 'network-response',
        });
        this.sourceNodeIds.push(sourceNodeId);
        return sourceNodeId;
      }

      return this.addNode('operation', funcName, line, column);
    }

    return undefined;
  }

  /**
   * Check if function is a taint sink
   */
  private isSinkFunction(funcName: string): boolean {
    const sinks = [
      // Command execution
      'exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync',
      // Code evaluation
      'eval', 'Function',
      // Network (only fetch for body/URL, not all network calls)
      'fetch',
      // File system
      'writeFile', 'writeFileSync', 'appendFile', 'appendFileSync',
      // Dynamic imports
      'require', 'import',
    ];

    return sinks.some((sink) => funcName === sink || funcName.endsWith(`.${sink}`));
  }

  /**
   * Get sink type based on function name
   */
  private getSinkType(funcName: string): string {
    if (funcName.includes('exec') || funcName.includes('spawn')) {
      return 'command-execution';
    }
    if (funcName === 'eval' || funcName === 'Function') {
      return 'code-evaluation';
    }
    if (funcName === 'fetch' || funcName.includes('axios') || funcName.includes('http')) {
      return 'network-request';
    }
    if (funcName.includes('write') || funcName.includes('append')) {
      return 'file-write';
    }
    if (funcName === 'require' || funcName === 'import') {
      return 'dynamic-import';
    }
    return 'unknown';
  }

  /**
   * Get function name from call expression
   */
  private getFunctionName(node: ts.CallExpression): string {
    const expr = node.expression;

    if (ts.isIdentifier(expr)) {
      return expr.getText();
    }

    if (ts.isPropertyAccessExpression(expr)) {
      return expr.name.getText();
    }

    return expr.getText();
  }

  /**
   * Get line number for node
   */
  private getLine(node: ts.Node): number {
    const sourceFile = node.getSourceFile();
    if (!sourceFile) return 0;
    const { line } = sourceFile.getLineAndCharacterOfPosition(node.getStart());
    return line + 1; // Convert to 1-indexed
  }

  /**
   * Get column number for node
   */
  private getColumn(node: ts.Node): number {
    const sourceFile = node.getSourceFile();
    if (!sourceFile) return 0;
    const { character } = sourceFile.getLineAndCharacterOfPosition(node.getStart());
    return character;
  }
}
