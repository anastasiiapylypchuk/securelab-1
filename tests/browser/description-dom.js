await (async () => {
  const MARKER_ID = "13daec59-505b-45c3-9ac1-8bf93eb1521f";
  const SEED_WITH_COMMENT_ID = "20000000-0000-0000-0000-000000000001";
  const NORMAL_TEXT_IDS = [
    "9801cf0c-a37b-405e-bd76-dea5d99d487c",
    "d9a41861-e327-44c9-a640-6f0f576f87a0",
    "4e7cae43-2ab6-46eb-9c90-e6fc4d804380",
    "e99395c3-a7bd-4153-8126-7de86d9301dc",
    "ec4ce385-e259-48d4-af8e-817c74da32ea",
    "20000000-0000-0000-0000-000000000003"
  ];

  const check = (condition, message) => { if (!condition) throw new Error(message); };
  const markerState = () =>
    document.querySelector("#lab05-marker-target").getAttribute("data-lab05-marker");
  const input = document.querySelector("#incident-id");
  const box = document.querySelector("#description");
  const comments = document.querySelector("#comments");

  async function renderFixture(id) {
    const response = await fetch(`/api/incidents/${encodeURIComponent(id)}`);
    check(response.status === 200, `Unexpected HTTP ${response.status} for ${id}`);
    const data = await response.json();
    input.value = id;
    await load();
    return data;
  }

  try {
    check(markerState() === null, "Reload before test");

    const marker = await renderFixture(MARKER_ID);
    check(marker.description.includes("data-lab05-marker"), "Wrong marker fixture");
    check(box.textContent === marker.description, "Description text changed");
    check(box.childElementCount === 0, "Description became HTML elements");

    const seed = await renderFixture(SEED_WITH_COMMENT_ID);
    const texts = (seed.comments ?? []).map(c => c.text);
    check(texts.some(t => t.includes("data-lab05-marker")), "Seed comment marker missing");
    const paragraphs = [...comments.children];
    check(paragraphs.length === texts.length, "Wrong comment count");
    paragraphs.forEach((p, i) => {
      check(p.childElementCount === 0, `Comment ${i} became HTML elements`);
      check(p.textContent === texts[i], `Comment ${i} text changed`);
    });
    await load();
    check(comments.children.length === texts.length, "Comments duplicated on re-render");

    for (const id of NORMAL_TEXT_IDS) {
      const data = await renderFixture(id);
      check(box.textContent === data.description, `Normal text changed: ${id}`);
      check(box.childElementCount === 0, `Normal text became HTML: ${id}`);
    }

    await new Promise(resolve => setTimeout(resolve, 500));
    check(markerState() === null, "Marker executed");

    console.log("PASS: description, comments, re-render and normal text rendered as plain text");
  } catch (error) {
    console.error(`FAIL: ${error.message}`);
  }
})();