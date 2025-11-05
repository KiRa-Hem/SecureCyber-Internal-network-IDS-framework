import networkx as nx
import matplotlib.pyplot as plt
import io
import base64
from typing import Dict, List, Any, Tuple
import json

class GraphAnalyzer:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.pos = None
        self.initialize_graph()
    
    def initialize_graph(self):
        """Initialize the network graph with default topology."""
        # Define nodes with types
        nodes = [
            ("router-1", {"type": "router", "level": 1}),
            ("router-2", {"type": "router", "level": 1}),
            ("fw-1", {"type": "firewall", "level": 2}),
            ("fw-2", {"type": "firewall", "level": 2}),
            ("switch-1", {"type": "switch", "level": 3}),
            ("switch-2", {"type": "switch", "level": 3}),
            ("switch-3", {"type": "switch", "level": 3}),
            ("switch-4", {"type": "switch", "level": 3}),
            ("web-01", {"type": "server", "level": 4}),
            ("web-02", {"type": "server", "level": 4}),
            ("db-01", {"type": "database", "level": 4}),
            ("app-01", {"type": "server", "level": 4}),
            ("user-01", {"type": "host", "level": 5}),
            ("user-02", {"type": "host", "level": 5}),
            ("user-03", {"type": "host", "level": 5}),
            ("user-04", {"type": "host", "level": 5})
        ]
        
        # Define edges
        edges = [
            ("router-1", "fw-1"),
            ("router-1", "fw-2"),
            ("router-2", "fw-1"),
            ("router-2", "fw-2"),
            ("fw-1", "switch-1"),
            ("fw-1", "switch-2"),
            ("fw-2", "switch-3"),
            ("fw-2", "switch-4"),
            ("switch-1", "web-01"),
            ("switch-2", "web-02"),
            ("switch-3", "db-01"),
            ("switch-4", "app-01"),
            ("web-01", "user-01"),
            ("web-01", "user-02"),
            ("web-02", "user-03"),
            ("db-01", "user-04"),
            ("app-01", "user-04")
        ]
        
        # Add nodes and edges to graph
        self.graph.add_nodes_from(nodes)
        self.graph.add_edges_from(edges)
        
        # Calculate positions
        self.pos = nx.spring_layout(self.graph, seed=42)
    
    def get_graph_data(self) -> Dict[str, Any]:
        """Get graph data for visualization."""
        nodes = []
        for node, data in self.graph.nodes(data=True):
            x, y = self.pos[node]
            nodes.append({
                "id": node,
                "x": float(x),
                "y": float(y),
                "type": data["type"],
                "level": data["level"]
            })
        
        edges = []
        for u, v in self.graph.edges():
            x1, y1 = self.pos[u]
            x2, y2 = self.pos[v]
            edges.append({
                "source": u,
                "target": v,
                "x1": float(x1),
                "y1": float(y1),
                "x2": float(x2),
                "y2": float(y2)
            })
        
        return {
            "nodes": nodes,
            "edges": edges
        }
    
    def highlight_attack_path(self, path: List[str]) -> Dict[str, Any]:
        """Highlight a path in the graph."""
        graph_data = self.get_graph_data()
        
        # Mark nodes in path
        for node in graph_data["nodes"]:
            node["in_path"] = node["id"] in path
        
        # Mark edges in path
        for edge in graph_data["edges"]:
            edge["in_path"] = (edge["source"] in path and edge["target"] in path)
        
        return graph_data
    
    def get_shortest_path(self, source: str, target: str) -> List[str]:
        """Get the shortest path between two nodes."""
        try:
            return nx.shortest_path(self.graph, source=source, target=target)
        except nx.NetworkXNoPath:
            return []
    
    def get_node_neighbors(self, node_id: str) -> List[str]:
        """Get neighbors of a node."""
        return list(self.graph.neighbors(node_id))
    
    def visualize_graph(self, highlight_nodes: List[str] = None) -> str:
        """Generate a base64 encoded image of the graph."""
        plt.figure(figsize=(12, 8))
        
        # Draw the graph
        node_colors = []
        for node in self.graph.nodes():
            if highlight_nodes and node in highlight_nodes:
                node_colors.append('red')
            else:
                node_types = self.graph.nodes[node]["type"]
                color_map = {
                    'router': 'blue',
                    'firewall': 'orange',
                    'switch': 'green',
                    'server': 'purple',
                    'database': 'brown',
                    'host': 'gray'
                }
                node_colors.append(color_map.get(node_types, 'gray'))
        
        nx.draw(self.graph, self.pos, with_labels=True, node_color=node_colors, 
                node_size=800, font_size=10, font_weight='bold', arrows=True)
        
        # Save to bytes
        buf = io.BytesIO()
        plt.savefig(buf, format='png')
        buf.seek(0)
        
        # Convert to base64
        img_base64 = base64.b64encode(buf.read()).decode('utf-8')
        plt.close()
        
        return img_base64