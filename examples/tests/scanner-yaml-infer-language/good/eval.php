<?php
// GOOD: PHP file. Scanner must NOT apply Python-only rule (inferred from path).
// If the loader defaults to "generic", this would wrongly get a finding.
eval($code);
