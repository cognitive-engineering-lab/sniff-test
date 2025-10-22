


# Phases
1. Get something out the door
    - any function with direct **unsafe axiom**s (e.g. ptr deref) should have an annotation explaining conditions
    - calling a function with an annotation requires justification at call site
        - for now, trust that dependencies are annotated correctly (changed in 2)
        - single level of annotation (changed in 3)
2. Different levels of annotations
    - annotations with specific conditions require specific justification
3. Check dependencies too
    - allow the checking of dependencies
