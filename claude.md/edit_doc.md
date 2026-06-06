# LaTeX Style Edit Prompt

Apply the following style rules to my LaTeX prose without rewriting the substance.

1. Light edit only. Preserve the author's wording, tone, structure, and intent. Do not add new ideas or expand on existing ones. Edit for style, not content.

2. Break long sentences. If a sentence exceeds roughly 35 words or contains more than one main clause joined by a comma, split it into two or more shorter sentences. Keep already-short sentences as they are.

3. No em dashes and no semicolons. Replace them with a period and a new sentence. If the connection between clauses is genuinely needed, use a conjunction such as *and*, *but*, *because*, or *while*.

4. Match the citation command to its grammatical role. Use `\citeA{author_year}` when the citation is part of the sentence flow, where the author name reads as a noun in the prose. For example, write "as reported by `\citeA{author_year}`". Use `\cite{author_year}` when the citation is a parenthetical aside that supports a statement or claim without being a grammatical part of it. For example, write "the value is X `\cite{author_year}`". Do not use a parenthetical `\cite{}` where the author name is meant to be read as part of the sentence, and do not use `\citeA{}` for a citation that merely backs a claim.

5. American English throughout. Use *characterize*, *summarize*, *analyze*, *neighbor*, *color*, *modeling*, *normalize*. No *-ise*, *-our*, or *-re* endings.

6. No manual line breaks inside paragraphs. Each paragraph is one continuous line of source. LaTeX handles wrapping.

7. Variable consistency in LaTeX.
   - The same variable must use the same notation everywhere. `$x_j$` and `$x_{j}$` render identically but read as inconsistent. Pick one and use it throughout.
   - Use the same subscript style across all variables in the document. If one variable uses `$x_j$`, another should not use `$x_{j}$`.
   - The same applies to fonts. Do not mix `$\mathbf{x}$` and `$\vec{x}$` for the same vector.

8. No symbol reuse across distinct concepts. If `$x$` already means final demand somewhere, do not also use it as the input to a fragility function. Each symbol means one thing only across the whole document.
   - When a scientific convention forces a symbol clash, for example `$\theta$` is the convention for the median fragility capacity but is also commonly used as an angle, keep the strict convention for the stronger claim and rename the weaker-claim variable using a distinct symbol, an alternative Greek letter, or a fancy script form such as `$\vartheta$`, `$\Theta$`, `$\tilde\theta$`, or `$\phi$`.
   - Flag any symbol clash you detect when reviewing my text, and propose a renaming.

9. The following phrasings are sometimes flagged as "AI-ish", but they match my writing preference. Do not hesitate to use them when they fit.
   - "It is worth noting that..."
   - "Importantly,..." / "Notably,..." / "Indeed,..."
   - "We can see that..."
   - "Furthermore", "Moreover", or "Additionally" as sentence openers when genuinely required.
   - Filler clauses such as "in essence", "in particular", "as such", "thus", or "thereby".
   - **Avoid** decorative tricolons such as "A, B, and C" when the third item is just padding.
   - **Avoid** qualifiers such as "relatively", "fairly", "quite", or "rather".
   - **Avoid** hedging stacks such as "may potentially" or "could possibly".

10. When you cannot avoid editing the substance, for example to fix a variable clash or an undefined symbol, call it out at the end of your response as a separate note. Do not silently rewrite content.

11. Preserve all existing references, equation labels, figure labels, and table labels exactly as given.

12. **Important.** All abbreviations must be defined on first appearance. Flag missing definitions instead of inventing them, unless the abbreviation is universally obvious such as NASA, NOAA, or US. This avoids misdefinition. For non-proper nouns, use lower case. Keep capitals for proper nouns such as NASA, BEA, and named federal or NGO entities.

13. **Important.** Do not invent citations. You may flag where a citation is needed, but do not ever insert a cite key, even if you are confident about the source.

14. **Terminology consistency.** Pick one term per concept and use it everywhere in the manuscript. Do not vary terminology for stylistic variety. Flag any inconsistency you detect when reviewing my text, with the two or more variants and a recommendation for which to standardize on. Examples of pairs to keep consistent:
    - "tropical cyclone wind" / "TC wind" / "hurricane wind" / "wind" — pick one for the hazard, define the abbreviation on first use, then reuse.
    - "framework" / "model" / "pipeline" / "module" / "approach" — these are not synonyms in technical writing. Use the one that fits and stick with it.
    - "substation" / "node" / "asset" — substation is a physical facility, node is a graph element, asset can mean either; do not interchange.
    - "expected daily damage" / "EAD" / "daily damage" / "daily loss" — define the acronym on first use, then use the acronym throughout. Do not switch back to the spelled-out form mid-document.
    - "freezing rain and wind gust" / "FZG" / "ice storm" / "compound winter hazard" — same rule.
    - "fragility function" / "fragility curve" / "damage function" — pick one.
    - "Sperry-Piltz" / "SPIA" / "Sperry–Piltz" — same spelling, same hyphen style throughout.
