import html
import json

from src.models.finding import FindingStatus


_NODE_COLORS = {
    "contract": "#58a6ff",
    "function_hot": "#f78166",
    "function": "#8b949e",
    "state_variable": "#d2a679",
    "modifier": "#bc8cff",
    "proven": "#3fb950",
}

_EDGE_COLORS = {
    "CALLS": "#58a6ff",
    "WRITES": "#f78166",
    "READS": "#8b949e",
    "INHERITS": "#bc8cff",
    "DEFINES": "#484f58",
    "HAS_MODIFIER": "#484f58",
    "EXTERNAL_CALL": "#f0883e",
}

_NODE_RADII = {
    "contract": 12,
    "function_hot": 10,
    "function": 6,
    "state_variable": 5,
    "modifier": 5,
    "proven": 14,
}


def _graph_to_d3_data(graph, findings) -> dict:
    """Convert NetworkX DiGraph to D3-compatible {nodes, links} dict."""
    proven_nodes: set[str] = set()
    for f in findings:
        if f.status == FindingStatus.PROVEN:
            for node_id in f.attack_path:
                proven_nodes.add(node_id)
            proven_nodes.add(f.hotspot_node_id)

    nodes = []
    node_ids_in_graph = set()
    for node_id, data in graph.nodes(data=True):
        node_ids_in_graph.add(node_id)
        node_type = data.get("type", "unknown")
        risk_score = data.get("risk_score", 0)
        is_proven = node_id in proven_nodes

        if is_proven:
            visual_type = "proven"
        elif node_type == "function" and risk_score >= 70:
            visual_type = "function_hot"
        else:
            visual_type = node_type

        nodes.append({
            "id": node_id,
            "type": node_type,
            "visualType": visual_type,
            "riskScore": risk_score,
            "proven": is_proven,
            "label": node_id.split("::")[-1] if "::" in node_id else node_id,
        })

    links = []
    for src, dst, data in graph.edges(data=True):
        if src not in node_ids_in_graph or dst not in node_ids_in_graph:
            continue
        rel = data.get("relationship", "CALLS")
        links.append({
            "source": src,
            "target": dst,
            "type": rel,
        })

    return {"nodes": nodes, "links": links}


def render_graph_html(graph, findings) -> str:
    """Returns a complete self-contained HTML string with an interactive force-directed graph."""
    d3_data = _graph_to_d3_data(graph, findings)
    d3_json = json.dumps(d3_data)

    node_colors_js = json.dumps(_NODE_COLORS)
    edge_colors_js = json.dumps(_EDGE_COLORS)
    node_radii_js = json.dumps(_NODE_RADII)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Critikal Attack Surface Graph</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0d1117;color:#c9d1d9;font-family:system-ui,-apple-system,sans-serif;overflow:hidden}}
#toolbar{{position:fixed;top:0;left:0;right:0;height:48px;background:#161b22;border-bottom:1px solid #30363d;display:flex;align-items:center;padding:0 16px;gap:10px;z-index:10}}
#toolbar h1{{font-size:14px;font-weight:600;color:#f0f6fc;white-space:nowrap}}
.filter-btn{{background:#21262d;color:#c9d1d9;border:1px solid #30363d;padding:4px 12px;border-radius:6px;cursor:pointer;font-size:12px}}
.filter-btn:hover{{background:#30363d}}
.filter-btn.active{{background:#1f6feb;border-color:#1f6feb;color:#fff}}
#legend{{position:fixed;bottom:16px;left:16px;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px;font-size:11px;z-index:10}}
#legend h3{{font-size:12px;margin-bottom:8px;color:#f0f6fc}}
.legend-row{{display:flex;align-items:center;gap:6px;margin:4px 0}}
.legend-dot{{width:10px;height:10px;border-radius:50%;flex-shrink:0}}
svg{{display:block;width:100vw;height:100vh;padding-top:48px}}
.tooltip{{position:fixed;background:#161b22;border:1px solid #30363d;border-radius:6px;padding:8px 12px;font-size:12px;pointer-events:none;z-index:20;display:none;max-width:320px}}
.tooltip .tt-id{{color:#58a6ff;font-weight:600;word-break:break-all}}
.tooltip .tt-row{{color:#8b949e;margin-top:2px}}
</style>
</head>
<body>
<div id="toolbar">
  <h1>Critikal Attack Surface</h1>
  <button class="filter-btn active" data-filter="all">All</button>
  <button class="filter-btn" data-filter="contracts">Contracts Only</button>
  <button class="filter-btn" data-filter="high">High Risk Only</button>
  <button class="filter-btn" data-filter="proven">Proven Path</button>
</div>
<div id="legend">
  <h3>Legend</h3>
  <div class="legend-row"><span class="legend-dot" style="background:#58a6ff"></span> Contract</div>
  <div class="legend-row"><span class="legend-dot" style="background:#f78166"></span> High-Risk Function</div>
  <div class="legend-row"><span class="legend-dot" style="background:#8b949e"></span> Function</div>
  <div class="legend-row"><span class="legend-dot" style="background:#d2a679"></span> State Variable</div>
  <div class="legend-row"><span class="legend-dot" style="background:#bc8cff"></span> Modifier / Inherits</div>
  <div class="legend-row"><span class="legend-dot" style="background:#3fb950;box-shadow:0 0 6px #3fb950"></span> Proven Finding</div>
</div>
<div class="tooltip" id="tooltip"></div>
<svg id="graph"></svg>
<script>
(function(){{
const DATA={d3_json};
const NODE_COLORS={node_colors_js};
const EDGE_COLORS={edge_colors_js};
const NODE_RADII={node_radii_js};

const svg=document.getElementById("graph");
const NS="http://www.w3.org/2000/svg";
const W=window.innerWidth,H=window.innerHeight-48;
svg.setAttribute("viewBox",`0 0 ${{W}} ${{H}}`);

/* ── Minimal force simulation ────────────────────────── */
const nodes=DATA.nodes.map((n,i)=>({{...n,x:W/2+(Math.random()-.5)*W*.4,y:H/2+(Math.random()-.5)*H*.4,vx:0,vy:0}}));
const nodeMap=Object.create(null);
nodes.forEach(n=>{{nodeMap[n.id]=n}});
const links=DATA.links.filter(l=>nodeMap[l.source]&&nodeMap[l.target]).map(l=>({{...l,src:nodeMap[l.source],tgt:nodeMap[l.target]}}));

function simulate(iterations){{
  const alpha0=1,decay=0.98,repulse=800,spring=0.005,idealLen=60,center=0.01;
  let alpha=alpha0;
  for(let iter=0;iter<iterations;iter++){{
    alpha*=decay;
    /* repulsion (Barnes-Hut would be better but N is small enough) */
    for(let i=0;i<nodes.length;i++){{
      for(let j=i+1;j<nodes.length;j++){{
        let dx=nodes[j].x-nodes[i].x,dy=nodes[j].y-nodes[i].y;
        let d2=dx*dx+dy*dy||1;
        let f=alpha*repulse/d2;
        let fx=dx*f,fy=dy*f;
        nodes[i].vx-=fx;nodes[i].vy-=fy;
        nodes[j].vx+=fx;nodes[j].vy+=fy;
      }}
    }}
    /* spring (links) */
    for(const l of links){{
      let dx=l.tgt.x-l.src.x,dy=l.tgt.y-l.src.y;
      let d=Math.sqrt(dx*dx+dy*dy)||1;
      let f=alpha*spring*(d-idealLen);
      let fx=dx/d*f,fy=dy/d*f;
      l.src.vx+=fx;l.src.vy+=fy;
      l.tgt.vx-=fx;l.tgt.vy-=fy;
    }}
    /* centering */
    for(const n of nodes){{
      n.vx+=(W/2-n.x)*center*alpha;
      n.vy+=(H/2-n.y)*center*alpha;
    }}
    /* integrate + damping */
    for(const n of nodes){{
      n.vx*=0.6;n.vy*=0.6;
      n.x+=n.vx;n.y+=n.vy;
      n.x=Math.max(20,Math.min(W-20,n.x));
      n.y=Math.max(20,Math.min(H-20,n.y));
    }}
  }}
}}

simulate(Math.min(300,80+nodes.length));

/* ── SVG rendering ───────────────────────────────────── */
const gMain=document.createElementNS(NS,"g");
gMain.setAttribute("id","main");
svg.appendChild(gMain);

const gLinks=document.createElementNS(NS,"g");
const gNodes=document.createElementNS(NS,"g");
gMain.appendChild(gLinks);gMain.appendChild(gNodes);

/* edges */
const linkEls=[];
for(const l of links){{
  const line=document.createElementNS(NS,"line");
  line.setAttribute("x1",l.src.x);line.setAttribute("y1",l.src.y);
  line.setAttribute("x2",l.tgt.x);line.setAttribute("y2",l.tgt.y);
  line.setAttribute("stroke",EDGE_COLORS[l.type]||"#484f58");
  line.setAttribute("stroke-width",l.type==="CALLS"?"1.2":"0.6");
  line.setAttribute("stroke-opacity","0.45");
  line.dataset.source=l.source;line.dataset.target=l.target;line.dataset.type=l.type;
  gLinks.appendChild(line);
  linkEls.push(line);
}}

/* nodes */
const circEls=[];
for(const n of nodes){{
  const g=document.createElementNS(NS,"g");
  g.setAttribute("transform",`translate(${{n.x}},${{n.y}})`);
  g.dataset.id=n.id;g.dataset.type=n.type;g.dataset.vtype=n.visualType;
  g.dataset.risk=n.riskScore;g.dataset.proven=n.proven?"1":"0";

  const r=NODE_RADII[n.visualType]||6;
  const c=document.createElementNS(NS,"circle");
  c.setAttribute("r",r);
  c.setAttribute("fill",NODE_COLORS[n.visualType]||"#8b949e");
  if(n.proven){{
    c.setAttribute("style","filter:drop-shadow(0 0 4px #3fb950)");
  }}
  g.appendChild(c);
  gNodes.appendChild(g);
  circEls.push(g);

  /* tooltip */
  g.addEventListener("mouseenter",e=>{{
    const tt=document.getElementById("tooltip");
    tt.innerHTML=`<div class="tt-id">${{esc(n.id)}}</div>`
      +`<div class="tt-row">Type: ${{esc(n.type)}}</div>`
      +`<div class="tt-row">Risk: ${{n.riskScore}}</div>`
      +(n.proven?`<div class="tt-row" style="color:#3fb950">PROVEN</div>`:"");
    tt.style.display="block";
    tt.style.left=(e.clientX+12)+"px";tt.style.top=(e.clientY+12)+"px";
  }});
  g.addEventListener("mousemove",e=>{{
    const tt=document.getElementById("tooltip");
    tt.style.left=(e.clientX+12)+"px";tt.style.top=(e.clientY+12)+"px";
  }});
  g.addEventListener("mouseleave",()=>{{
    document.getElementById("tooltip").style.display="none";
  }});

  /* click: highlight attack path for proven nodes */
  g.addEventListener("click",()=>{{
    if(!n.proven) return;
    circEls.forEach(el=>el.querySelector("circle").setAttribute("stroke","none"));
    linkEls.forEach(el=>el.setAttribute("stroke-opacity","0.45"));
    /* find connected proven nodes via links */
    const connected=new Set([n.id]);
    links.forEach(l=>{{
      if(l.src.proven&&l.tgt.proven){{connected.add(l.source);connected.add(l.target)}}
    }});
    circEls.forEach(el=>{{
      if(connected.has(el.dataset.id)){{
        const cc=el.querySelector("circle");
        cc.setAttribute("stroke","#3fb950");cc.setAttribute("stroke-width","3");
      }}
    }});
    linkEls.forEach(el=>{{
      if(connected.has(el.dataset.source)&&connected.has(el.dataset.target)){{
        el.setAttribute("stroke-opacity","1");el.setAttribute("stroke","#3fb950");
      }}
    }});
  }});
}}

function esc(s){{const d=document.createElement("div");d.textContent=s;return d.innerHTML}}

/* ── Zoom & Pan ──────────────────────────────────────── */
let scale=1,tx=0,ty=0,dragging=false,startX,startY;
function applyTransform(){{gMain.setAttribute("transform",`translate(${{tx}},${{ty}}) scale(${{scale}})`)}}
svg.addEventListener("wheel",e=>{{
  e.preventDefault();
  const factor=e.deltaY<0?1.1:0.9;
  const rect=svg.getBoundingClientRect();
  const mx=e.clientX-rect.left,my=e.clientY-rect.top;
  tx=mx-(mx-tx)*factor;ty=my-(my-ty)*factor;
  scale*=factor;applyTransform();
}},{{passive:false}});
svg.addEventListener("mousedown",e=>{{
  if(e.target.closest("circle")) return;
  dragging=true;startX=e.clientX-tx;startY=e.clientY-ty;svg.style.cursor="grabbing";
}});
window.addEventListener("mousemove",e=>{{
  if(!dragging) return;tx=e.clientX-startX;ty=e.clientY-startY;applyTransform();
}});
window.addEventListener("mouseup",()=>{{dragging=false;svg.style.cursor=""}});

/* ── Filters ─────────────────────────────────────────── */
document.querySelectorAll(".filter-btn").forEach(btn=>{{
  btn.addEventListener("click",()=>{{
    document.querySelectorAll(".filter-btn").forEach(b=>b.classList.remove("active"));
    btn.classList.add("active");
    const f=btn.dataset.filter;
    circEls.forEach(el=>{{
      let show=true;
      if(f==="contracts") show=el.dataset.type==="contract";
      else if(f==="high") show=parseInt(el.dataset.risk)>=70;
      else if(f==="proven") show=el.dataset.proven==="1";
      el.style.display=show?"":"none";
    }});
    linkEls.forEach(el=>{{
      let show=true;
      if(f==="contracts") show=false;
      else if(f==="high"){{
        const sn=nodeMap[el.dataset.source],tn=nodeMap[el.dataset.target];
        show=(sn&&sn.riskScore>=70)&&(tn&&tn.riskScore>=70);
      }}
      else if(f==="proven"){{
        const sn=nodeMap[el.dataset.source],tn=nodeMap[el.dataset.target];
        show=(sn&&sn.proven)&&(tn&&tn.proven);
      }}
      el.style.display=show?"":"none";
    }});
  }});
}});
}})();
</script>
</body>
</html>"""
