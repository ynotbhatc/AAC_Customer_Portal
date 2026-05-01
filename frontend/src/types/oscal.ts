/**
 * OSCAL Assessment Results — subset of the full NIST OSCAL schema.
 * Spec: https://pages.nist.gov/OSCAL/reference/latest/assessment-results/
 *
 * Maps from AAC compliance_results PostgreSQL table.
 */

export interface OscalAssessmentResults {
  "assessment-results": {
    uuid: string;
    metadata: OscalMetadata;
    "import-ap": { href: string };
    results: OscalResult[];
  };
}

export interface OscalMetadata {
  title: string;
  "last-modified": string;
  version: string;
  "oscal-version": "1.1.2";
  remarks?: string;
}

export interface OscalResult {
  uuid: string;
  title: string;
  description: string;
  start: string;
  end: string;
  "reviewed-controls": {
    "control-selections": OscalControlSelection[];
  };
  observations: OscalObservation[];
  findings: OscalFinding[];
}

export interface OscalControlSelection {
  description: string;
  "include-controls": { "control-id": string }[];
}

export interface OscalObservation {
  uuid: string;
  title: string;
  description: string;
  methods: string[];
  subjects: { "subject-uuid": string; type: string }[];
  "collected": string;
  "relevant-evidence": { description: string; href?: string }[];
}

export interface OscalFinding {
  uuid: string;
  title: string;
  description: string;
  target: {
    type: "statement-id" | "objective-id";
    "target-id": string;
    status: { state: "satisfied" | "not-satisfied" };
  };
  "related-observations": { "observation-uuid": string }[];
}
