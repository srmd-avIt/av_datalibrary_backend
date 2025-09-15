// src/server/index.js

const express = require('express');
const cors = require('cors');
const db = require('./db'); // This now imports the mysql2 pool
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());



// =================================================================
const buildWhereClause = (queryParams, searchFields = [], allColumns = []) => {
    const { page, limit, search, ...filters } = queryParams;
    const whereClauses = [];
    let params = [];

    // 1. Handle Global Search
    if (search && searchFields.length > 0) {
        const searchConditions = searchFields.map(field => `${db.escapeId(field)} LIKE ?`).join(' OR ');
        whereClauses.push(`(${searchConditions})`);
        const searchPattern = `%${search}%`;
        searchFields.forEach(() => params.push(searchPattern));
    }

    // 2. Handle Detailed Filters
    Object.keys(filters).forEach(key => {
        const filterValue = queryParams[key];
        const fieldName = key.replace(/_min|_max$/, '');
        
        if (allColumns.length > 0 && !allColumns.includes(fieldName)) {
            return;
        }

        if (key.endsWith('_min')) {
            whereClauses.push(`${db.escapeId(fieldName)} >= ?`);
            params.push(filterValue);
        } else if (key.endsWith('_max')) {
            whereClauses.push(`${db.escapeId(fieldName)} <= ?`);
            params.push(filterValue);
        } else if (Array.isArray(filterValue) && filterValue.length > 0) {
            const hasEmptyFilter = filterValue.includes('__EMPTY__');
            const otherValues = filterValue.filter(v => v !== '__EMPTY__');
            let clauseParts = [];
            if (hasEmptyFilter) {
                clauseParts.push(`(${db.escapeId(fieldName)} IS NULL OR ${db.escapeId(fieldName)} = '')`);
            }
            if (otherValues.length > 0) {
                const placeholders = otherValues.map(() => '?').join(',');
                clauseParts.push(`${db.escapeId(fieldName)} IN (${placeholders})`);
                params = params.concat(otherValues);
            }
            if (clauseParts.length > 0) {
                whereClauses.push(`(${clauseParts.join(' OR ')})`);
            }
        } else if (typeof filterValue === 'string' && filterValue.trim() !== '') {
            whereClauses.push(`${db.escapeId(fieldName)} LIKE ?`);
            params.push(`%${filterValue}%`);
        }
    });

    return { whereString: whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '', params };
};


// =================================================================
// API ENDPOINTS
// =================================================================

// --- Events Endpoints ---
app.get('/api/events', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;
    const { whereString, params } = buildWhereClause(req.query, ['EventCode', 'EventName', 'Yr'], ['EventID', 'EventCode', 'Yr', 'EventName' /* add more... */]);
    const countQuery = `SELECT COUNT(*) as total FROM Events ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);
    const dataQuery = `SELECT * FROM Events ${whereString} LIMIT ? OFFSET ?`;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);
    res.json({ data: results, totalPages, currentPage: page });
  } catch (err) { res.status(500).json({ error: 'Database query failed' }); }
});

app.get('/api/events/export', async (req, res) => {
  try {
    // FIX: Call the generic buildWhereClause function
    const { whereString, params } = buildWhereClause(req.query, ['EventCode', 'EventName', 'Yr'], ['EventID', 'EventCode', 'Yr','SubmittedDate','FromDate','ToDate', 'EventName','fkEventCategory','EventsRemarks','EventMonth','CommonId','IsSubEvent1','IsAudioRecorded','PravachanCount','UdhgoshCount','PaglaCount','PratisthaCount','SummaryRemarks','Pra-SU-duration','LastModifiedBy','LastModifiedTimestamp','NewEventFrom','NewEventTo' /* add more... */]);
    const dataQuery = `SELECT * FROM Events ${whereString}`;
    const [results] = await db.query(dataQuery, params);

    if (results.length === 0) {
      return res.status(404).send("No data found to export for the given filters.");
    }

    const headers = Object.keys(results[0]);
    const csvHeader = headers.join(',');
    const csvRows = results.map(row => headers.map(header => {
        const value = row[header];
        const strValue = String(value === null || value === undefined ? '' : value);
        return `"${strValue.replace(/"/g, '""')}"`;
    }).join(','));
    const csvContent = [csvHeader, ...csvRows].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="events_export.csv"');
    res.status(200).send(csvContent);

  } catch (err) {
    console.error("Database query error on /api/users/export:", err);
    res.status(500).json({ error: 'CSV export failed' });
  }
});





// --- NewMediaLog Endpoints ---
app.get('/api/newmedialog', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;
    const { whereString, params } = buildWhereClause(req.query, ['MLUniqueID', 'Topic', 'SpeakerSinger'], ['MLUniqueID','FootageSrNo', 'LogSerialNo','fkDigitalRecordingCode','ContentFrom','ContentTo', 'TimeOfDay','fkOccasion','EditingStatus','FootageType','VideoDistribution','Details','SubDetails','CounterFrom','CounterTo','SubDuration','TotalDuration','Language','SpeakerSinger','fkOrganization','Designation','fkCountry','fkState','fkCity','Venue','fkGranth','Number','Topic','Seriesname','SatsangStart','SatsangEnd','IsAudioRecorded','AudioMP3Distribution','AudioWAVDistribution','AudioMP3DRCode','AudioWAVDRCode','Remarks','IsStartPage','EndPage','IsInformal','IsPPGNotPresent','Guidance','DiskMasterDuration','EventRefRemarksCounters','EventRefMLID','EventRefMLID2', 'DubbedLanguage','DubbingArtist','HasSubtitle','SubTitlesLanguage','EditingDeptRemarks','EditingType','BhajanType','IsDubbed','NumberSource','TopicSource','LastModifiedTimestamp','LastModifiedBy','Synopsis','LocationWithinAshram','Keywords','Grading' ,'Segment Category','SegmentDuration','TopicgivenBy' /* add more... */]);
    const countQuery = `SELECT COUNT(*) as total FROM NewMediaLog ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);
    const dataQuery = `SELECT * FROM NewMediaLog ${whereString} LIMIT ? OFFSET ?`;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);
    res.json({ data: results, totalPages, currentPage: page });
  } catch (err) {
    console.error("Database query error on /api/newmedialog:", err);
    res.status(500).json({ error: 'Database query failed' });
  }
});

// server.js

app.get('/api/newmedialog/all-except-satsang', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;

    // The exact WHERE clause from your provided query
    const whereClause = `
     WHERE nml.\`Segment Category\` NOT IN (
        'Prasangik Udbodhan', 'SU', 'SU - GM', 'SU - Revision', 
        'Satsang', 'Informal Satsang', 'SU - Extracted'
      )
      AND (
          dr.PreservationStatus IS NULL
          OR TRIM(dr.PreservationStatus) = ''
          OR UPPER(TRIM(dr.PreservationStatus)) = 'Preserve'
      )
      AND  (
          nml.\`IsInformal\` IS NULL
          OR TRIM(nml.\`IsInformal\`) = ''
          OR UPPER(TRIM(nml.\`IsInformal\`)) = 'No'
   )
    `;

    const countQuery = `
      SELECT COUNT(*) as total 
      FROM NewMediaLog AS nml 
      LEFT JOIN DigitalRecordings AS dr ON nml.fkDigitalRecordingCode = dr.RecordingCode
      ${whereClause}
    `;
    const [[{ total }]] = await db.query(countQuery);
    const totalPages = Math.ceil(total / limit);

    const dataQuery = `
      SELECT 
        nml.*,
        dr.PreservationStatus,
        dr.RecordingCode,
        dr.RecordingName,
        dr.fkEventCode
      FROM NewMediaLog AS nml
      LEFT JOIN DigitalRecordings AS dr ON nml.fkDigitalRecordingCode = dr.RecordingCode
      ${whereClause}
      ORDER BY nml.MLUniqueID DESC
      LIMIT ? OFFSET ?
    `;
    const [rows] = await db.query(dataQuery, [limit, offset]);
    
    res.json({ data: rows, totalPages: totalPages, currentPage: page });
  } catch (err) {
    console.error('API Error for satsang-extracted-clips:', err);
    res.status(500).json({ error: err.message });
  }
});

// --- Corrected Endpoint for "Satsang Extracted Clips" (Using your query) ---
app.get('/api/newmedialog/satsang-extracted-clips', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;

    // The exact WHERE clause from your provided query
    const whereClause = `
      WHERE nml.\`Segment Category\` IN (
           'Product/Webseries',
           'SU - Extracted',
           'Satsang Clips'
      )
      AND (
          dr.PreservationStatus IS NULL
          OR TRIM(dr.PreservationStatus) = ''
          OR UPPER(TRIM(dr.PreservationStatus)) = 'PRESERVE'
      )
    `;

    const countQuery = `
      SELECT COUNT(*) as total 
      FROM NewMediaLog AS nml 
      LEFT JOIN DigitalRecordings AS dr ON nml.fkDigitalRecordingCode = dr.RecordingCode
      ${whereClause}
    `;
    const [[{ total }]] = await db.query(countQuery);
    const totalPages = Math.ceil(total / limit);

    const dataQuery = `
      SELECT 
        nml.*,
        dr.PreservationStatus,
        dr.RecordingCode,
        dr.RecordingName,
        dr.fkEventCode
      FROM NewMediaLog AS nml
      LEFT JOIN DigitalRecordings AS dr ON nml.fkDigitalRecordingCode = dr.RecordingCode
      ${whereClause}
      ORDER BY nml.MLUniqueID DESC
      LIMIT ? OFFSET ?
    `;
    const [rows] = await db.query(dataQuery, [limit, offset]);
    
    res.json({ data: rows, totalPages: totalPages, currentPage: page });
  } catch (err) {
    console.error('API Error for satsang-extracted-clips:', err);
    res.status(500).json({ error: err.message });
  }
});


// --- Corrected Endpoint for "Satsang Category" (Using your query) ---
app.get('/api/newmedialog/satsang-category', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;

    // The exact WHERE clause from your provided query
    const whereClause = `
      WHERE nml.\`Segment Category\` IN (
          'Prasangik Udbodhan', 'SU', 'SU - GM', 'SU - Revision', 
          'Satsang', 'Informal Satsang', 'SU - Extracted'
      )
      AND (
          dr.PreservationStatus IS NULL
          OR TRIM(dr.PreservationStatus) = ''
          OR UPPER(TRIM(dr.PreservationStatus)) = 'PRESERVE'
      )
    `;

    const countQuery = `
      SELECT COUNT(*) as total 
      FROM NewMediaLog AS nml 
      LEFT JOIN DigitalRecordings AS dr ON nml.fkDigitalRecordingCode = dr.RecordingCode
      ${whereClause}
    `;
    const [[{ total }]] = await db.query(countQuery);
    const totalPages = Math.ceil(total / limit);

    const dataQuery = `
      SELECT 
        nml.*,
        dr.PreservationStatus,
        dr.RecordingCode,
        dr.RecordingName,
        dr.fkEventCode
      FROM NewMediaLog AS nml
      LEFT JOIN DigitalRecordings AS dr ON nml.fkDigitalRecordingCode = dr.RecordingCode
      ${whereClause}
      ORDER BY nml.MLUniqueID DESC
      LIMIT ? OFFSET ?
    `;
    const [rows] = await db.query(dataQuery, [limit, offset]);

    res.json({ data: rows, totalPages: totalPages, currentPage: page });
  } catch (err) {
    console.error('API Error for satsang-category:', err);
    res.status(500).json({ error: err.message });
  }
});



app.get('/api/newmedialog/export', async (req, res) => {
    try {
        // FIX: Call the generic buildWhereClause function
        const { whereString, params } = buildWhereClause(req.query, ['MLUniqueID', 'Topic', 'SpeakerSinger'], ['MLUniqueID','FootageSrNo', 'LogSerialNo','fkDigitalRecordingCode','ContentFrom','ContentTo', 'TimeOfDay','fkOccasion','EditingStatus','FootageType','VideoDistribution','Details','SubDetails','CounterFrom','CounterTo','SubDuration','TotalDuration','Language','SpeakerSinger','fkOrganization','Designation','fkCountry','fkState','fkCity','Venue','fkGranth','Number','Topic','Seriesname','SatsangStart','SatsangEnd','IsAudioRecorded','AudioMP3Distribution','AudioWAVDistribution','AudioMP3DRCode','AudioWAVDRCode','Remarks','IsStartPage','EndPage','IsInformal','IsPPGNotPresent','Guidance','DiskMasterDuration','EventRefRemarksCounters','EventRefMLID','EventRefMLID2', 'DubbedLanguage','DubbingArtist','HasSubtitle','SubTitlesLanguage','EditingDeptRemarks','EditingType','BhajanType','IsDubbed','NumberSource','TopicSource','LastModifiedTimestamp','LastModifiedBy','Synopsis','LocationWithinAshram','Keywords','Grading' ,'Segment Category','SegmentDuration','TopicgivenBy' /* add more... */]);
        const dataQuery = `SELECT * FROM NewMediaLog ${whereString}`;
        const [results] = await db.query(dataQuery, params);
        if (results.length === 0) {
            return res.status(404).send("No data found to export for the given filters.");
        }
        const headers = Object.keys(results[0]);
        const csvHeader = headers.join(',');
        const csvRows = results.map(row => headers.map(header => {
            const value = row[header];
            const strValue = String(value === null || value === undefined ? '' : value);
            return `"${strValue.replace(/"/g, '""')}"`;
        }).join(','));
        const csvContent = [csvHeader, ...csvRows].join('\n');
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename="newmedialog_export.csv"');
        res.status(200).send(csvContent);
    } catch (err) {
        console.error("Database query error on /api/newmedialog/export:", err);
        res.status(500).json({ error: 'CSV export failed' });
    }
});


// --- UPGRADED DigitalRecording Endpoints ---
app.get('/api/digitalrecording', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;
    const { whereString, params } = buildWhereClause(req.query, ['fkEventCode', 'RecordingName'], ['fkEventCode', 'RecordingName', 'RecordingCode', 'NoOfFiles', 'FilesizeInBytes']);
    const countQuery = `SELECT COUNT(*) as total FROM DigitalRecordings ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);
    const dataQuery = `SELECT * FROM DigitalRecordings ${whereString} LIMIT ? OFFSET ?`;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);
    res.json({ data: results, totalPages, currentPage: page });
  } catch (err) {
    console.error("Database query error on /api/digitalrecording:", err);
    res.status(500).json({ error: 'Database query failed' });
  }
});

app.get('/api/digitalrecording/export', async (req, res) => {
    try {
        const { whereString, params } = buildWhereClause(req.query, ['fkEventCode', 'RecordingName'], ['fkEventCode', 'RecordingName', 'RecordingCode', 'NoOfFiles','fkDigitalMasterCategory','fkMediaName','BitRate','AudioBitrate','Filesize','Duration','AudioTotalDuration','RecordingRemarks','CounterError','ReasonError','QcRemarksCheckedOn','PreservationStatus','QcSevak','MasterProductTitle','Qcstatus','LastModifiedTimestamp','fkDistributionLabel','SubmittedDate','PresStatGuidDt','InfoOnCassette','Masterquality','IsInformal', 'FilesizeInBytes','AssociatedDR','Dimension','ProductionBucket','DistributionDriveLink','Teams']);
        const dataQuery = `SELECT * FROM DigitalRecordings ${whereString}`;
        const [results] = await db.query(dataQuery, params);
        if (results.length === 0) {
            return res.status(404).send("No data found to export for the given filters.");
        }
        const headers = Object.keys(results[0]);
        const csvHeader = headers.join(',');
        const csvRows = results.map(row => headers.map(header => {
            const value = row[header];
            const strValue = String(value === null || value === undefined ? '' : value);
            return `"${strValue.replace(/"/g, '""')}"`;
        }).join(','));
        const csvContent = [csvHeader, ...csvRows].join('\n');
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename="digitalrecordings_export.csv"');
        res.status(200).send(csvContent);
    } catch (err) {
        console.error("Database query error on /api/digitalrecording/export:", err);
        res.status(500).json({ error: 'CSV export failed' });
    }
});

// --- NEW ENDPOINTS FOR AUXFILES TABLE ---

// Endpoint to get all records from the AuxFiles table
app.get('/api/auxfiles', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;
    const { whereString, params } = buildWhereClause(req.query, ['AuxCode', 'AuxTopic', 'NotesRemarks'], ['AUXID', 'new_auxid', 'AuxCode', 'fkMLID', 'NoOfFiles', 'FilesizeBytes', 'ProjFileSize' /* Add all filterable columns */]);
    const countQuery = `SELECT COUNT(*) as total FROM AuxFiles ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);
    const dataQuery = `SELECT * FROM AuxFiles ${whereString} LIMIT ? OFFSET ?`;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);
    res.json({ data: results, totalPages, currentPage: page });
  } catch (err) {
    console.error("Database query error on /api/auxfiles:", err);
    res.status(500).json({ error: 'Database query failed' });
  }
});

app.get('/api/auxfiles/export', async (req, res) => {
    try {
        const { whereString, params } = buildWhereClause(req.query, ['AuxCode', 'AuxTopic', 'NotesRemarks'], ['AUXID', 'new_auxid', 'AuxCode', 'AuxFileType','AuxLanguage','fkMLID','AuxTopic','NotesRemarks','GoogleDriveLink', 'NoOfFiles', 'FilesizeBytes', 'LastModifiedTimestamp','LastModifiedBy','ProjFileCode','ProjFileSize' , 'ProjFileName','SRTLink','CreatedOn','CreatedBy' ,'ModifiedOn','ModifiedBy' ]);
        const dataQuery = `SELECT * FROM AuxFiles ${whereString}`;
        const [results] = await db.query(dataQuery, params);
        if (results.length === 0) {
            return res.status(404).send("No data found to export for the given filters.");
        }
        const headers = Object.keys(results[0]);
        const csvHeader = headers.join(',');
        const csvRows = results.map(row => headers.map(header => {
            const value = row[header];
            const strValue = String(value === null || value === undefined ? '' : value);
            return `"${strValue.replace(/"/g, '""')}"`;
        }).join(','));
        const csvContent = [csvHeader, ...csvRows].join('\n');
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename="auxfiles_export.csv"');
        res.status(200).send(csvContent);
    } catch (err) {
        console.error("Database query error on /api/auxfiles/export:", err);
        res.status(500).json({ error: 'CSV export failed' });
    }
});

// Endpoint to get a single auxiliary file by its code
app.get('/api/auxfiles/:fkMLID', async (req, res) => {
    const { fkMLID } = req.params;
    try {
        const [results] = await db.query('SELECT * FROM AuxFiles WHERE fkMLID = ?', [fkMLID]);

        if (results.length === 0) {
            return res.status(404).json({ message: `Auxiliary file with code ${fkMLID} not found.` });
        }
        res.json(results[0]);
    } catch (err) {
        console.error("Database query error on single auxiliary file:", err);
        return res.status(500).json({ error: 'Database query failed' });
    }
});


// --- ENDPOINTS FOR SINGLE RECORDS ---

// Endpoint to get a single event by EventCode
app.get('/api/events/:eventCode', async (req, res) => { // Added async
    const { eventCode } = req.params;
    try {
        const [results] = await db.query('SELECT * FROM Events WHERE EventCode = ?', [eventCode]);

        if (results.length === 0) {
            return res.status(404).json({ message: `Event with code ${eventCode} not found.` });
        }
        res.json(results[0]);
    } catch (err) {
        console.error("Database query error on single event:", err);
        return res.status(500).json({ error: 'Database query failed' });
    }
});

// Endpoint to get a single digital recording
app.get('/api/digitalrecording/:recordingCode', async (req, res) => { // Added async
    const { recordingCode } = req.params;
    try {
        const [results] = await db.query('SELECT * FROM DigitalRecordings WHERE RecordingCode = ?', [recordingCode]);

        if (results.length === 0) {
            return res.status(404).json({ message: `Digital Recording with code ${recordingCode} not found.` });
        }
        res.json(results[0]);
    } catch (err) {
        console.error("Database query error on single digital recording:", err);
        return res.status(500).json({ error: 'Database query failed' });
    }
});

// --- NEW ENDPOINT FOR SINGLE NEW MEDIA LOG ---
app.get('/api/newmedialog/:mlid', async (req, res) => {
    // FIX: Use 'mlid' to match the route parameter name
    const { mlid } = req.params;
    try {
        // FIX: Use the 'mlid' variable in the query
        const [results] = await db.query('SELECT * FROM NewMediaLog WHERE MLUniqueID = ?', [mlid]);

        if (results.length === 0) {
            // FIX: Use 'mlid' in the error message for correct debugging
            return res.status(404).json({ message: `Media Log with ID ${mlid} not found.` });
        }
        res.json(results[0]);
    } catch (err) {
        console.error("Database query error on single media log:", err);
        return res.status(500).json({ error: 'Database query failed' });
    }
});

app.get('/api/dashboard/countries-visited', async (req, res) => {
    const { year } = req.query;

    if (!year) {
        return res.status(400).json({ error: 'Year query parameter is required.' });
    }

    try {
        const query = `
            SELECT
    nml.fkCountry AS name,
    COUNT(*) AS visits
FROM Events AS e
INNER JOIN DigitalRecordings AS dr 
    ON e.EventCode = dr.fkEventCode
INNER JOIN NewMediaLog AS nml 
    ON dr.RecordingCode = nml.fkDigitalRecordingCode
WHERE
    e.Yr = ?
    AND nml.fkCountry IS NOT NULL
    AND nml.fkCountry <> ''
GROUP BY
    nml.fkCountry
ORDER BY
    visits DESC -- Limit to a reasonable number for a chart
        `;

        const [results] = await db.query(query, [year]);
        res.json(results);

    } catch (err) {
        console.error("Database query error on /api/dashboard/countries-visited:", err);
        res.status(500).json({ error: 'Failed to fetch dashboard data' });
    }
});


// --- NEW ENDPOINT FOR EVENT DETAILS BY COUNTRY AND YEAR ---
app.get('/api/dashboard/events-by-country', async (req, res) => {
    const { year, country } = req.query;

    if (!year || !country) {
        return res.status(400).json({ error: 'Year and Country query parameters are required.' });
    }

    try {
        const query = `
             SELECT
                e.EventCode,
                e.EventName,
                nml.Detail,
                dr.RecordingCode,
                nml.fkCountry,
                nml.fkCity,              -- ✅ Added city info
                nml.*,
                COUNT(*) OVER (PARTITION BY nml.fkCountry) AS visits_for_country
            FROM Events AS e
            INNER JOIN DigitalRecordings AS dr 
                ON e.EventCode = dr.fkEventCode
            INNER JOIN NewMediaLog AS nml 
                ON dr.RecordingCode = nml.fkDigitalRecordingCode
            WHERE
                e.Yr = ?
                AND nml.fkCountry IS NOT NULL
                AND nml.fkCountry <> ''
                AND nml.fkCountry = ?
            ORDER BY
                visits_for_country DESC, 
                nml.fkCity; -- ✅ Optional: order by city inside the country
        `;

        const [results] = await db.query(query, [year, country]);
        res.json(results);

    } catch (err) {
        console.error("Database query error on /api/dashboard/events-by-country:", err);
        res.status(500).json({ error: 'Failed to fetch event details' });
    }
});

// --- NEW ENDPOINT FOR CITIES VISITED ---
app.get('/api/dashboard/cities-visited', async (req, res) => {
    const { year } = req.query;

    if (!year) {
        return res.status(400).json({ error: 'Year query parameter is required.' });
    }

    try {
        const query = `
            SELECT
                nml.fkCity AS name,
                COUNT(*) AS visits
            FROM Events AS e
            INNER JOIN DigitalRecordings AS dr 
                ON e.EventCode = dr.fkEventCode
            INNER JOIN NewMediaLog AS nml 
                ON dr.RecordingCode = nml.fkDigitalRecordingCode
            WHERE
                e.Yr = ?
                AND nml.fkCity IS NOT NULL
                AND nml.fkCity <> ''
            GROUP BY 
                nml.fkCity
            ORDER BY 
                visits DESC
             -- Get the top 10 cities
        `;

        const [results] = await db.query(query, [year]);
        res.json(results);

    } catch (err) {
        console.error("Database query error on /api/dashboard/cities-visited:", err);
        res.status(500).json({ error: 'Failed to fetch city data' });
    }
});

// --- ADD THIS NEW ENDPOINT for fetching details by city ---
app.get('/api/dashboard/events-by-city', async (req, res) => {
    const { year, city } = req.query;

    if (!year || !city) {
        return res.status(400).json({ error: 'Year and City query parameters are required.' });
    }

    try {
        const query = `
              SELECT
                e.EventCode,
                e.EventName,
                e.FromDate,
                e.ToDate,
                nml.MLUniqueID,
                nml.Detail AS Detail, -- Aliased for consistency
                nml.fkCity,
                nml.fkCountry
            FROM Events AS e
            INNER JOIN DigitalRecordings AS dr ON e.EventCode = dr.fkEventCode
            INNER JOIN NewMediaLog AS nml ON dr.RecordingCode = nml.fkDigitalRecordingCode
            WHERE e.Yr = ? AND nml.fkCity = ?
            ORDER BY e.FromDate, nml.LogSerialNo;
        `;

        const [results] = await db.query(query, [year, city]);
        res.json(results);

    } catch (err) {
        console.error("Database query error on /api/dashboard/events-by-city:", err);
        res.status(500).json({ error: 'Failed to fetch event details for city' });
    }
});


// In a real application, this might come from a dedicated 'countries' table in your DB.
// ✅ Define this BEFORE any routes
const countryCoordinates = {
  'Afghanistan': { lat: 33.9391, lng: 67.7100 },
  'Albania': { lat: 41.1533, lng: 20.1683 },
  'Algeria': { lat: 28.0339, lng: 1.6596 },
  'Andorra': { lat: 42.5063, lng: 1.5218 },
  'Angola': { lat: -11.2027, lng: 17.8739 },
  'Antigua and Barbuda': { lat: 17.0608, lng: -61.7964 },
  'Argentina': { lat: -38.4161, lng: -63.6167 },
  'Armenia': { lat: 40.0691, lng: 45.0382 },
  'Australia': { lat: -25.2744, lng: 133.7751 },
  'Austria': { lat: 47.5162, lng: 14.5501 },
  'Azerbaijan': { lat: 40.1431, lng: 47.5769 },
  'Bahamas': { lat: 25.0343, lng: -77.3963 },
  'Bahrain': { lat: 26.0667, lng: 50.5577 },
  'Bangladesh': { lat: 23.6850, lng: 90.3563 },
  'Barbados': { lat: 13.1939, lng: -59.5432 },
  'Belarus': { lat: 53.7098, lng: 27.9534 },
  'Belgium': { lat: 50.8503, lng: 4.3517 },
  'Belize': { lat: 17.1899, lng: -88.4976 },
  'Benin': { lat: 9.3077, lng: 2.3158 },
  'Bhutan': { lat: 27.5142, lng: 90.4336 },
  'Bolivia': { lat: -16.2902, lng: -63.5887 },
  'Bosnia and Herzegovina': { lat: 43.9159, lng: 17.6791 },
  'Botswana': { lat: -22.3285, lng: 24.6849 },
  'Brazil': { lat: -14.2350, lng: -51.9253 },
  'Brunei': { lat: 4.5353, lng: 114.7277 },
  'Bulgaria': { lat: 42.7339, lng: 25.4858 },
  'Burkina Faso': { lat: 12.2383, lng: -1.5616 },
  'Burundi': { lat: -3.3731, lng: 29.9189 },
  'Cambodia': { lat: 12.5657, lng: 104.9910 },
  'Cameroon': { lat: 7.3697, lng: 12.3547 },
  'Canada': { lat: 56.1304, lng: -106.3468 },
  'Chile': { lat: -35.6751, lng: -71.5430 },
  'China': { lat: 35.8617, lng: 104.1954 },
  'Colombia': { lat: 4.5709, lng: -74.2973 },
  'Costa Rica': { lat: 9.7489, lng: -83.7534 },
  'Croatia': { lat: 45.1000, lng: 15.2000 },
  'Cuba': { lat: 21.5218, lng: -77.7812 },
  'Cyprus': { lat: 35.1264, lng: 33.4299 },
  'Czech Republic': { lat: 49.8175, lng: 15.4730 },
  'Denmark': { lat: 56.2639, lng: 9.5018 },
  'Dominican Republic': { lat: 18.7357, lng: -70.1627 },
  'Ecuador': { lat: -1.8312, lng: -78.1834 },
  'Egypt': { lat: 26.8206, lng: 30.8025 },
  'El Salvador': { lat: 13.7942, lng: -88.8965 },
  'Estonia': { lat: 58.5953, lng: 25.0136 },
  'Ethiopia': { lat: 9.1450, lng: 40.4897 },
  'Finland': { lat: 61.9241, lng: 25.7482 },
  'France': { lat: 46.6034, lng: 1.8883 },
  'Germany': { lat: 51.1657, lng: 10.4515 },
  'Greece': { lat: 39.0742, lng: 21.8243 },
  'Hungary': { lat: 47.1625, lng: 19.5033 },
  'Iceland': { lat: 64.9631, lng: -19.0208 },
  'India': { lat: 20.5937, lng: 78.9629 },
  'Indonesia': { lat: -0.7893, lng: 113.9213 },
  'Iran': { lat: 32.4279, lng: 53.6880 },
  'Iraq': { lat: 33.2232, lng: 43.6793 },
  'Ireland': { lat: 53.3331, lng: -8.0 },
  'Israel': { lat: 31.0461, lng: 34.8516 },
  'Italy': { lat: 41.8719, lng: 12.5674 },
  'Japan': { lat: 36.2048, lng: 138.2529 },
  'Kenya': { lat: -0.0236, lng: 37.9062 },
  'Kuwait': { lat: 29.3117, lng: 47.4818 },
  'Latvia': { lat: 56.8796, lng: 24.6032 },
  'Lebanon': { lat: 33.8547, lng: 35.8623 },
  'Lithuania': { lat: 55.1694, lng: 23.8813 },
  'Luxembourg': { lat: 49.8153, lng: 6.1296 },
  'Malaysia': { lat: 4.2105, lng: 101.9758 },
  'Mexico': { lat: 23.6345, lng: -102.5528 },
  'Morocco': { lat: 31.7917, lng: -7.0926 },
  'Nepal': { lat: 28.3949, lng: 84.1240 },
  'Netherlands': { lat: 52.1326, lng: 5.2913 },
  'New Zealand': { lat: -40.9006, lng: 174.8860 },
  'Nigeria': { lat: 9.0820, lng: 8.6753 },
  'Norway': { lat: 60.4720, lng: 8.4689 },
  'Oman': { lat: 21.4735, lng: 55.9754 },
  'Pakistan': { lat: 30.3753, lng: 69.3451 },
  'Panama': { lat: 8.5380, lng: -80.7821 },
  'Paraguay': { lat: -23.4425, lng: -58.4438 },
  'Peru': { lat: -9.1900, lng: -75.0152 },
  'Philippines': { lat: 12.8797, lng: 121.7740 },
  'Poland': { lat: 51.9194, lng: 19.1451 },
  'Portugal': { lat: 39.3999, lng: -8.2245 },
  'Qatar': { lat: 25.276987, lng: 51.520008 },
  'Romania': { lat: 45.9432, lng: 24.9668 },
  'Russia': { lat: 61.5240, lng: 105.3188 },
  'Saudi Arabia': { lat: 23.8859, lng: 45.0792 },
  'Singapore': { lat: 1.3521, lng: 103.8198 },
  'Slovakia': { lat: 48.6690, lng: 19.6990 },
  'Slovenia': { lat: 46.1512, lng: 14.9955 },
  'South Africa': { lat: -30.5595, lng: 22.9375 },
  'South Korea': { lat: 35.9078, lng: 127.7669 },
  'Spain': { lat: 40.4637, lng: -3.7492 },
  'Sri Lanka': { lat: 7.8731, lng: 80.7718 },
  'Sweden': { lat: 60.1282, lng: 18.6435 },
  'Switzerland': { lat: 46.8182, lng: 8.2275 },
  'Thailand': { lat: 15.8700, lng: 100.9925 },
  'Turkey': { lat: 38.9637, lng: 35.2433 },
  'UAE': { lat: 23.4241, lng: 53.8478 },
  'UK': { lat: 55.3781, lng: -3.4360 },
  'USA': { lat: 37.0902, lng: -95.7129 },
  'Ukraine': { lat: 48.3794, lng: 31.1656 },
  'Uruguay': { lat: -32.5228, lng: -55.7658 },
  'Uzbekistan': { lat: 41.3775, lng: 64.5853 },
  'Venezuela': { lat: 6.4238, lng: -66.5897 },
  'Vietnam': { lat: 14.0583, lng: 108.2772 },
  'Yemen': { lat: 15.5527, lng: 48.5164 },
  'Zambia': { lat: -13.1339, lng: 27.8493 },
  'Zimbabwe': { lat: -19.0154, lng: 29.1549 }
};

// Optional normalization mapping
const countryNameMapping = {
  'Afghanistan': 'Afghanistan',
  'Albania': 'Albania',
  'Algeria': 'Algeria',
  'Andorra': 'Andorra',
  'Angola': 'Angola',
  'Argentina': 'Argentina',
  'Armenia': 'Armenia',
  'Australia': 'Australia',
  'Austria': 'Austria',
  'Azerbaijan': 'Azerbaijan',
  'Bahamas': 'Bahamas',
  'Bahrain': 'Bahrain',
  'Bangladesh': 'Bangladesh',
  'Barbados': 'Barbados',
  'Belarus': 'Belarus',
  'Belgium': 'Belgium',
  'Belize': 'Belize',
  'Benin': 'Benin',
  'Bhutan': 'Bhutan',
  'Bolivia': 'Bolivia',
  'Bosnia and Herzegovina': 'Bosnia and Herzegovina',
  'Botswana': 'Botswana',
  'Brazil': 'Brazil',
  'Brunei': 'Brunei',
  'Bulgaria': 'Bulgaria',
  'Burkina Faso': 'Burkina Faso',
  'Burundi': 'Burundi',
  'Cambodia': 'Cambodia',
  'Cameroon': 'Cameroon',
  'Canada': 'Canada',
  'Chile': 'Chile',
  'China': 'China',
  'Colombia': 'Colombia',
  'Costa Rica': 'Costa Rica',
  'Croatia': 'Croatia',
  'Cuba': 'Cuba',
  'Cyprus': 'Cyprus',
  'Czech Republic': 'Czech Republic',
  'Denmark': 'Denmark',
  'Dominican Republic': 'Dominican Republic',
  'Ecuador': 'Ecuador',
  'Egypt': 'Egypt',
  'El Salvador': 'El Salvador',
  'Estonia': 'Estonia',
  'Ethiopia': 'Ethiopia',
  'Finland': 'Finland',
  'France': 'France',
  'Germany': 'Germany',
  'Greece': 'Greece',
  'Hungary': 'Hungary',
  'Iceland': 'Iceland',
  'India': 'India',
  'Indonesia': 'Indonesia',
  'Iran': 'Iran',
  'Iraq': 'Iraq',
  'Ireland': 'Ireland',
  'Israel': 'Israel',
  'Italy': 'Italy',
  'Jamaica': 'Jamaica',
  'Japan': 'Japan',
  'Jordan': 'Jordan',
  'Kazakhstan': 'Kazakhstan',
  'Kenya': 'Kenya',
  'Kuwait': 'Kuwait',
  'Kyrgyzstan': 'Kyrgyzstan',
  'Laos': 'Laos',
  'Latvia': 'Latvia',
  'Lebanon': 'Lebanon',
  'Lithuania': 'Lithuania',
  'Luxembourg': 'Luxembourg',
  'Madagascar': 'Madagascar',
  'Malaysia': 'Malaysia',
  'Mexico': 'Mexico',
  'Mongolia': 'Mongolia',
  'Morocco': 'Morocco',
  'Myanmar': 'Myanmar',
  'Nepal': 'Nepal',
  'Netherlands': 'Netherlands',
  'New Zealand': 'New Zealand',
  'Nigeria': 'Nigeria',
  'North Korea': 'North Korea',
  'Norway': 'Norway',
  'Oman': 'Oman',
  'Pakistan': 'Pakistan',
  'Panama': 'Panama',
  'Paraguay': 'Paraguay',
  'Peru': 'Peru',
  'Philippines': 'Philippines',
  'Poland': 'Poland',
  'Portugal': 'Portugal',
  'Qatar': 'Qatar',
  'Romania': 'Romania',
  'Russia': 'Russia',
  'Saudi Arabia': 'Saudi Arabia',
  'Serbia': 'Serbia',
  'Singapore': 'Singapore',
  'Slovakia': 'Slovakia',
  'Slovenia': 'Slovenia',
  'South Africa': 'South Africa',
  'South Korea': 'South Korea',
  'Spain': 'Spain',
  'Sri Lanka': 'Sri Lanka',
  'Sudan': 'Sudan',
  'Sweden': 'Sweden',
  'Switzerland': 'Switzerland',
  'Syria': 'Syria',
  'Taiwan': 'Taiwan',
  'Tajikistan': 'Tajikistan',
  'Tanzania': 'Tanzania',
  'Thailand': 'Thailand',
  'Tunisia': 'Tunisia',
  'Turkey': 'Turkey',
  'Turkmenistan': 'Turkmenistan',
  'Uganda': 'Uganda',
  'Ukraine': 'Ukraine',
  'United Arab Emirates': 'UAE',
  'UAE': 'UAE',
  'United Kingdom': 'UK',
  'UK': 'UK',
  'United States': 'USA',
  'USA': 'USA',
  'Uruguay': 'Uruguay',
  'Uzbekistan': 'Uzbekistan',
  'Venezuela': 'Venezuela',
  'Vietnam': 'Vietnam',
  'Yemen': 'Yemen',
  'Zambia': 'Zambia',
  'Zimbabwe': 'Zimbabwe'
};


// --- NEW ENDPOINT FOR GLOBAL MAP DISTRIBUTION DATA ---
app.get('/api/dashboard/global-distribution', async (req, res) => {
    const { year } = req.query;

    if (!year) {
        return res.status(400).json({ error: 'Year query parameter is required.' });
    }

    try {
        // This is your new, more detailed query integrated into the endpoint.
        const query = `
      SELECT
    nml.fkCountry AS country,
    e.Yr AS year,   -- ✅ include year in result if you want to show it
    SUM(
        CASE
            WHEN nml.Detail LIKE '%Pratishtha%'
              OR nml.Detail LIKE '%Sthapna%'
              OR nml.SubDetail LIKE '%Pratishtha%'
              OR nml.SubDetail LIKE '%Sthapna%'
            THEN 1 ELSE 0 END
    ) AS pratishthas,
    SUM(
        CASE
            WHEN nml.Detail LIKE '%Padhramani%'
              OR nml.Detail LIKE '%Pagla%'
              OR nml.SubDetail LIKE '%Padhramani%'
              OR nml.SubDetail LIKE '%Pagla%'
            THEN 1 ELSE 0 END
    ) AS padhramanis
FROM Events AS e
INNER JOIN DigitalRecordings AS dr
    ON e.EventCode = dr.fkEventCode
INNER JOIN NewMediaLog AS nml
    ON dr.RecordingCode = nml.fkDigitalRecordingCode
WHERE
    e.Yr = ?                          -- ✅ filter by selected year
    AND nml.FootageType <> 'Glimpses'
    AND nml.EditingStatus NOT LIKE '%title%'
    AND dr.PreservationStatus = 'Preserve'
    AND nml.fkCountry IS NOT NULL
    AND nml.fkCountry <> ''
GROUP BY
    nml.fkCountry, e.Yr
ORDER BY
    country ASC;

        `;

        const [results] = await db.query(query, [year]);

        // Post-process to add coordinates and format for the frontend
        // This part is crucial for compatibility with your React component
        const dataWithCoords = results.map(row => {
            const normalizedName = countryNameMapping[row.country] || row.country;
            return {
                name: normalizedName,
                pratishthas: row.pratishthas,
                padhramanis: row.padhramanis,
                lat: countryCoordinates[normalizedName]?.lat || 0,
                lng: countryCoordinates[normalizedName]?.lng || 0,
            };
        }).filter(country => country.lat !== 0 || country.lng !== 0);

        res.json(dataWithCoords);
    } catch (err) {
        console.error("Database query error on /api/dashboard/global-distribution:", err);
        res.status(500).json({ error: 'Failed to fetch global distribution data' });
    }
});



// in src/server/index.js

// --- NEW ENDPOINT: Fetch only Pratishtha events for a country and year ---
app.get('/api/dashboard/pratishtha-events', async (req, res) => {
    const { year, country } = req.query;

    if (!year || !country) {
        return res.status(400).json({ error: 'Year and Country are required.' });
    }

    try {
        // Using the query you provided
        const query = `
          SELECT
    e.EventCode,
    e.EventName,
    e.FromDate,
    e.ToDate,
    nml.fkCity,
    GROUP_CONCAT(DISTINCT nml.Detail ORDER BY nml.Detail SEPARATOR ', ') AS ContentDetails
FROM Events AS e
INNER JOIN DigitalRecordings AS dr
    ON e.EventCode = dr.fkEventCode
INNER JOIN NewMediaLog AS nml
    ON dr.RecordingCode = nml.fkDigitalRecordingCode
WHERE e.Yr = ?
  AND nml.fkCountry = ?
  AND (
       nml.Detail LIKE '%Pratishtha%'
    OR nml.Detail LIKE '%Sthapna%'
    OR nml.SubDetail LIKE '%Pratishtha%'
    OR nml.SubDetail LIKE '%Sthapna%'
  )
GROUP BY e.EventCode, e.EventName, e.FromDate, e.ToDate, nml.fkCity
ORDER BY e.FromDate ASC;

        `;
        const [results] = await db.query(query, [year, country]);
        res.json(results);
    } catch (err) {
        console.error("Database query error on /pratishtha-events:", err);
        res.status(500).json({ error: 'Failed to fetch Pratishtha events' });
    }
});

// --- NEW ENDPOINT: Fetch only Padhramani events for a country and year ---
app.get('/api/dashboard/padhramani-events', async (req, res) => {
    const { year, country } = req.query;

    if (!year || !country) {
        return res.status(400).json({ error: 'Year and Country are required.' });
    }

    try {
        // Using the query you provided
        const query = `
           SELECT
                e.EventCode,
                e.EventName,
                e.FromDate,
                e.ToDate,
                nml.fkCity,
                GROUP_CONCAT(DISTINCT nml.Detail ORDER BY nml.Detail SEPARATOR ', ') AS ContentDetails
            FROM Events AS e
            INNER JOIN DigitalRecordings AS dr
                ON e.EventCode = dr.fkEventCode
            INNER JOIN NewMediaLog AS nml
                ON dr.RecordingCode = nml.fkDigitalRecordingCode
            WHERE e.Yr = ?
              AND nml.fkCountry = ?
              AND (
                   nml.Detail LIKE '%Padhramani%'
                OR nml.Detail LIKE '%Pagla%'
                OR nml.SubDetail LIKE '%Padhramani%'
                OR nml.SubDetail LIKE '%Pagla%'
              )
            GROUP BY e.EventCode, e.EventName, e.FromDate, e.ToDate, nml.fkCity
            ORDER BY e.FromDate ASC;
        `;
        const [results] = await db.query(query, [year, country]);
        res.json(results);
    } catch (err) {
        console.error("Database query error on /padhramani-events:", err);
        res.status(500).json({ error: 'Failed to fetch Padhramani events' });
    }
});




// in src/server/index.js

// --- ADD THIS NEW ENDPOINT for the grouped event view ---
app.get('/api/dashboard/events-by-group', async (req, res) => {
    const { year, country, city } = req.query;

    if (!year || (!country && !city)) {
        return res.status(400).json({ error: 'Year and either Country or City are required.' });
    }

    try {
        let whereClause = 'e.Yr = ?';
        const params = [year];

        if (country) {
            whereClause += ' AND nml.fkCountry = ?';
            params.push(country);
        } else { // city must be present
            whereClause += ' AND nml.fkCity = ?';
            params.push(city);
        }

        const query = `
            SELECT
                e.EventCode,
                e.EventName,
                e.FromDate,
                e.ToDate,
                nml.fkCity,
                nml.fkCountry,
                COUNT(nml.MLUniqueID) AS ContentCount
            FROM Events AS e
            INNER JOIN DigitalRecordings AS dr ON e.EventCode = dr.fkEventCode
            INNER JOIN NewMediaLog AS nml ON dr.RecordingCode = nml.fkDigitalRecordingCode
            WHERE ${whereClause}
            GROUP BY 
                e.EventCode, e.EventName, e.FromDate, e.ToDate, nml.fkCity, nml.fkCountry
            ORDER BY 
                e.FromDate ASC;
        `;
        
        const [results] = await db.query(query, params);
        res.json(results);

    } catch (err) {
        console.error("Database query error on /api/dashboard/events-by-group:", err);
        res.status(500).json({ error: 'Failed to fetch grouped event data' });
    }
});

app.get('/api/dashboard/pratishtha-events-by-group', async (req, res) => {
    const { year, country } = req.query;

    if (!year || !country) {
        return res.status(400).json({ error: 'Year and Country are required.' });
    }

    try {
        const query = `
            SELECT
                e.EventCode,
                e.EventName,
                e.FromDate,
                e.ToDate,
                nml.fkCity,
                nml.fkCountry,
                COUNT(nml.MLUniqueID) AS ContentCount
            FROM Events AS e
            INNER JOIN DigitalRecordings AS dr ON e.EventCode = dr.fkEventCode
            INNER JOIN NewMediaLog AS nml ON dr.RecordingCode = nml.fkDigitalRecordingCode
            WHERE e.Yr = ? 
              AND nml.fkCountry = ? 
              AND e.EventName LIKE '%Pratishtha%'
            GROUP BY 
                e.EventCode, e.EventName, e.FromDate, e.ToDate, nml.fkCity, nml.fkCountry
            ORDER BY 
                e.FromDate ASC;
        `;
        
        const [results] = await db.query(query, [year, country]);
        res.json(results);

    } catch (err) {
        console.error("Database query error on /api/dashboard/pratishtha-events-by-group:", err);
        res.status(500).json({ error: 'Failed to fetch grouped Pratishtha event data' });
    }
});

// --- NEW ENDPOINT 2: Grouped Padhramani Events ---
app.get('/api/dashboard/padhramani-events-by-group', async (req, res) => {
    const { year, country } = req.query;

    if (!year || !country) {
        return res.status(400).json({ error: 'Year and Country are required.' });
    }

    try {
        const query = `
            SELECT
                e.EventCode,
                e.EventName,
                e.FromDate,
                e.ToDate,
                nml.fkCity,
                nml.fkCountry,
                COUNT(nml.MLUniqueID) AS ContentCount
            FROM Events AS e
            INNER JOIN DigitalRecordings AS dr ON e.EventCode = dr.fkEventCode
            INNER JOIN NewMediaLog AS nml ON dr.RecordingCode = nml.fkDigitalRecordingCode
            WHERE e.Yr = ? 
              AND nml.fkCountry = ? 
              AND e.EventName LIKE '%Padhramani%'
            GROUP BY 
                e.EventCode, e.EventName, e.FromDate, e.ToDate, nml.fkCity, nml.fkCountry
            ORDER BY 
                e.FromDate ASC;
        `;
        
        const [results] = await db.query(query, [year, country]);
        res.json(results);

    } catch (err) {
        console.error("Database query error on /api/dashboard/padhramani-events-by-group:", err);
        res.status(500).json({ error: 'Failed to fetch grouped Padhramani event data' });
    }
});
// Start server
const PORT = process.env.PORT || 3600;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});