-- Site capacity caps (s-H4): NULL = uncapped. At capacity, ENTRY crossings
-- are refused (403) so crowding turns into denial, not just an alert.
ALTER TABLE sites ADD COLUMN capacity INT;
