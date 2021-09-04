ALTER TABLE ONLY mitre.cpe_compl_cpe
    ADD CONSTRAINT cpe_to_cpe_compl_cpe FOREIGN KEY (cpe_id) REFERENCES mitre.cpe(id);

ALTER TABLE ONLY mitre.cve_node_cpe
    ADD CONSTRAINT cpe_to_cve_node_cpe FOREIGN KEY (cpe_id) REFERENCES mitre.cpe(id);
