// src/server/index.js

const express = require('express');
const cors = require("cors");
const db = require('./db'); // This now imports the mysql2 pool
const { google } = require("googleapis");
const nodemailer = require("nodemailer");
const app = express();
app.use(cors());
app.use(express.json());


const oAuth2Client = new google.auth.OAuth2(
  process.env.CLIENT_ID,
  process.env.CLIENT_SECRET,
  "https://developers.google.com/oauthplayground"
);
oAuth2Client.setCredentials({ refresh_token: process.env.REFRESH_TOKEN });

async function sendInvitationEmail({ email, role, teams, message, appLink }) {
  const accessToken = await oAuth2Client.getAccessToken();
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      type: "OAuth2",
      user: process.env.EMAIL_USER,
      clientId: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      refreshToken: process.env.REFRESH_TOKEN,
      accessToken: accessToken.token,
    },
  });

  const mailOptions = {
    from: `"AV Data Library" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "You're Invited!",
    text: `Role: ${role}\nTeams: ${teams.join(", ")}\nMessage: ${message}\nApp Link: ${appLink}`,
    html: `
      <p><strong>Role:</strong> ${role}</p>
      <p><strong>Teams:</strong> ${teams.join(", ")}</p>
      <p><strong>Message:</strong> ${message}</p>
      <p><a href="${appLink}">Join the app</a></p>
    `,
  };

  return transporter.sendMail(mailOptions);
}

app.post('/send-invitation', async (req, res) => {
  const { email, role, teams, message, appLink } = req.body;
  try {
    await sendInvitationEmail({ email, role, teams, message, appLink });
    res.status(200).json({ message: "Invitation sent successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

require('dotenv').config();




// ✅ UPGRADED: This function translates API parameters (start_date) to database columns (FromDate)
// It uses DATE() for robust, timezone-agnostic comparisons.
// ✅ Refactored buildWhereClause (no start_date / end_date filter)
// src/server/index.js

// ✅ REPLACEMENT for your buildWhereClause function
const buildWhereClause = (queryParams, searchFields = [], allColumns = []) => {
    // This map correctly matches the operators sent by the frontend.
    const allowedOperators = {
        'contains': 'LIKE', 'not_contains': 'NOT LIKE', 'equals': '=', 'not_equals': '!=',
        'starts_with': 'LIKE', 'ends_with': 'LIKE', 'in': 'IN', 'not_in': 'NOT IN',
        'greater': '>', 'greater_equal': '>=', 'less': '<', 'less_equal': '<=',
        'is_empty': 'IS_EMPTY', 'is_not_empty': 'IS_NOT_EMPTY', 'between': 'BETWEEN',
    };

    const { page, limit, search, advanced_filters, ...filters } = queryParams;
    const whereClauses = [];
    let params = [];

    // --- 1. Handle Global Search (Unchanged) ---
    if (search && searchFields.length > 0) {
        const searchConditions = searchFields
            .map(field => `${db.escapeId(field)} LIKE ?`)
            .join(' OR ');
        whereClauses.push(`(${searchConditions})`);
        params.push(...searchFields.map(() => `%${search}%`));
    }

    // --- 2. Handle Simple Key-Value Filters (Unchanged) ---
    Object.keys(filters).forEach(key => {
        const filterValue = queryParams[key];
        const fieldName = key.replace(/_min|_max$/, '');
        if (allColumns.length > 0 && !allColumns.includes(fieldName)) return;
        if (key.endsWith('_min')) {
            whereClauses.push(`${db.escapeId(fieldName)} >= ?`);
            params.push(filterValue);
        } else if (key.endsWith('_max')) {
            whereClauses.push(`${db.escapeId(fieldName)} <= ?`);
            params.push(filterValue);
        } else if (typeof filterValue === 'string' && filterValue.trim() !== '' && filterValue !== 'all') {
            whereClauses.push(`${db.escapeId(fieldName)} = ?`);
            params.push(filterValue);
        }
    });

    // --- 3. Handle Advanced Filters JSON (Completely Reworked) ---
    if (advanced_filters) {
        try {
            const filterGroups = JSON.parse(advanced_filters);
            if (!Array.isArray(filterGroups) || filterGroups.length === 0) {
                return { whereString: '', params };
            }

            const groupSqlParts = []; // Will hold final SQL for each group like "(c1 AND c2)"

            filterGroups.forEach((group, groupIndex) => {
                if (!group.rules || group.rules.length === 0) return;

                const ruleSqlParts = []; // Will hold individual rule parts like "field = ?", "AND field > ?"

                group.rules.forEach((rule, ruleIndex) => {
                    const operatorKey = String(rule.operator).toLowerCase();
                    if (!rule.field || !operatorKey || !allColumns.includes(rule.field) || !allowedOperators[operatorKey]) {
                        return; // Skip invalid rule
                    }

                    const field = db.escapeId(rule.field);
                    const dbOperator = allowedOperators[operatorKey];
                    let ruleClause = null;
                    const ruleParams = [];

                    // --- Generate clause for this specific rule ---
                    switch (dbOperator) {
                        case 'IS_EMPTY':
                            ruleClause = `(${field} IS NULL OR ${field} = '')`;
                            break;
                        case 'IS_NOT_EMPTY':
                            ruleClause = `(${field} IS NOT NULL AND ${field} <> '')`;
                            break;
                        case 'BETWEEN':
                            if (Array.isArray(rule.value) && rule.value.length === 2) {
                                ruleParams.push(rule.value[0], rule.value[1]);
                                ruleClause = `${field} BETWEEN ? AND ?`;
                            }
                            break;
                        case 'IN':
                        case 'NOT IN':
                            const inValues = Array.isArray(rule.value) ? rule.value : [rule.value];
                            if (inValues.length > 0) {
                                const placeholders = inValues.map(() => '?').join(',');
                                ruleParams.push(...inValues);
                                ruleClause = `${field} ${dbOperator} (${placeholders})`;
                            }
                            break;
                        case 'LIKE':
                        case 'NOT LIKE':
                            let paramValue = `%${rule.value}%`; // Default for 'contains'
                            if (operatorKey === 'starts_with') paramValue = `${rule.value}%`;
                            if (operatorKey === 'ends_with') paramValue = `%${rule.value}`;
                            ruleParams.push(paramValue);
                            ruleClause = `${field} ${dbOperator} ?`;
                            break;
                        default: // Handles =, !=, >, <, >=, <=
                            ruleParams.push(rule.value);
                            ruleClause = `${field} ${dbOperator} ?`;
                            break;
                    }

                    // --- Assemble the rule with its logic operator ---
                    if (ruleClause) {
                        // For any rule after the first, prepend its logic (AND/OR)
                        if (ruleIndex > 0) {
                            ruleSqlParts.push(rule.logic || 'AND');
                        }
                        ruleSqlParts.push(ruleClause);
                        params.push(...ruleParams);
                    }
                });

                // --- Assemble the group with its logic operator ---
                if (ruleSqlParts.length > 0) {
                    const groupClause = `(${ruleSqlParts.join(' ')})`;
                    
                    // For any group after the first, prepend its logic (AND/OR)
                    if (groupIndex > 0) {
                        // The logic is defined on the group itself. The UI default for new groups is OR.
                        groupSqlParts.push(group.logic || 'OR');
                    }
                    groupSqlParts.push(groupClause);
                }
            });

            if (groupSqlParts.length > 0) {
                // Wrap the entire advanced filter block in parentheses for safety
                whereClauses.push(`(${groupSqlParts.join(' ')})`);
            }

        } catch (e) {
            console.error("❌ Failed to parse advanced_filters:", e);
        }
    }

    return {
        whereString: whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '',
        params
    };
};


// Helper for sorting
const buildOrderByClause = (queryParams, allowedColumns = []) => {
    let { sortBy, sortDirection } = queryParams;
    const direction = (String(sortDirection).toUpperCase() === 'DESC') ? 'DESC' : 'ASC';
    if (sortBy && allowedColumns.includes(sortBy)) {
        return `ORDER BY ${db.escapeId(sortBy)} ${direction}`;
    }
    return '';
};


// --- Events Endpoint ---
// --- Events Endpoint ---
app.get('/api/events', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;

    // Normalize dates (force YYYY-MM-DD)
    function normalizeDate(d) {
      return d ? new Date(d).toISOString().slice(0, 10) : null;
    }
    req.query.start_date = normalizeDate(req.query.start_date);
    req.query.end_date = normalizeDate(req.query.end_date);

    const filterableColumns = [
      'EventID','EventCode','Yr','SubmittedDate','FromDate','ToDate',
      'EventName','fkEventCategory','EventRemarks','EventMonth','CommonId',
      'IsSubEvent1','IsAudioRecorded','PravachanCount','UdhgoshCount',
      'PaglaCount','PratisthaCount','SummaryRemarks','Pra-SU-duration',
      'LastModifiedBy','LastModifiedTimestamp','NewEventFrom','NewEventTo'
    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      ['EventID','EventCode','Yr','SubmittedDate','FromDate','ToDate',
      'EventName','fkEventCategory','EventRemarks','EventMonth','CommonId',
      'IsSubEvent1','IsAudioRecorded','PravachanCount','UdhgoshCount',
      'PaglaCount','PratisthaCount','SummaryRemarks','Pra-SU-duration',
      'LastModifiedBy','LastModifiedTimestamp','NewEventFrom','NewEventTo'], // searchable fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM Events ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `SELECT * FROM Events ${whereString} ${orderByString} LIMIT ? OFFSET ?`;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages
      }
    });
  } catch (err) {
    console.error("❌ DB Error:", err);
    res.status(500).json({ error: 'Database query failed' });
  }
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

    const filterableColumns = [
      'MLUniqueID','FootageSrNo', 'LogSerialNo','fkDigitalRecordingCode','ContentFrom','ContentTo',
      'TimeOfDay','fkOccasion','EditingStatus','FootageType','VideoDistribution','Detail','SubDetail',
      'CounterFrom','CounterTo','SubDuration','TotalDuration','Language','SpeakerSinger','fkOrganization',
      'Designation','fkCountry','fkState','fkCity','Venue','fkGranth','Number','Topic','Seriesname',
      'SatsangStart','SatsangEnd','IsAudioRecorded','AudioMP3Distribution','AudioWAVDistribution',
      'AudioMP3DRCode','AudioWAVDRCode','Remarks','IsStartPage','EndPage','IsInformal','IsPPGNotPresent',
      'Guidance','DiskMasterDuration','EventRefRemarksCounters','EventRefMLID','EventRefMLID2',
      'DubbedLanguage','DubbingArtist','HasSubtitle','SubTitlesLanguage','EditingDeptRemarks','EditingType',
      'BhajanType','IsDubbed','NumberSource','TopicSource','LastModifiedTimestamp','LastModifiedBy',
      'Synopsis','LocationWithinAshram','Keywords','Grading','Segment Category','Segment Duration',
      'TopicgivenBy'
    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      [ 'MLUniqueID','FootageSrNo', 'LogSerialNo','fkDigitalRecordingCode','ContentFrom','ContentTo',
      'TimeOfDay','fkOccasion','EditingStatus','FootageType','VideoDistribution','Detail','SubDetail',
      'CounterFrom','CounterTo','SubDuration','TotalDuration','Language','SpeakerSinger','fkOrganization',
      'Designation','fkCountry','fkState','fkCity','Venue','fkGranth','Number','Topic','Seriesname',
      'SatsangStart','SatsangEnd','IsAudioRecorded','AudioMP3Distribution','AudioWAVDistribution',
      'AudioMP3DRCode','AudioWAVDRCode','Remarks','IsStartPage','EndPage','IsInformal','IsPPGNotPresent',
      'Guidance','DiskMasterDuration','EventRefRemarksCounters','EventRefMLID','EventRefMLID2',
      'DubbedLanguage','DubbingArtist','HasSubtitle','SubTitlesLanguage','EditingDeptRemarks','EditingType',
      'BhajanType','IsDubbed','NumberSource','TopicSource','LastModifiedTimestamp','LastModifiedBy',
      'Synopsis','LocationWithinAshram','Keywords','Grading','Segment Category','Segment Duration',
      'TopicgivenBy'], // global search fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM NewMediaLog ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT * 
      FROM NewMediaLog 
      ${whereString} 
      ${orderByString} 
      LIMIT ? OFFSET ?
    `;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages
      }
    });
  } catch (err) {
    console.error("❌ Database query error on /api/newmedialog:", err);
    res.status(500).json({ error: 'Database query failed' });
  }
});


// server.js

app.get('/api/newmedialog/all-except-satsang', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;

    const whereClause = `
      WHERE nml.\`Segment Category\` NOT IN (
        'Prasangik Udbodhan', 'SU', 'SU - GM', 'SU - Revision', 
        'Satsang', 'Informal Satsang', 'SU - Extracted'
      )
      AND (
        dr.PreservationStatus IS NULL
        OR TRIM(dr.PreservationStatus) = ''
        OR UPPER(TRIM(dr.PreservationStatus)) = 'PRESERVE'
      )
      AND (
        nml.\`IsInformal\` IS NULL
        OR TRIM(nml.\`IsInformal\`) = ''
        OR UPPER(TRIM(nml.\`IsInformal\`)) = 'NO'
      )
    `;

    // --- Count Query ---
    const countQuery = `
      SELECT COUNT(*) as total
      FROM NewMediaLog AS nml
      LEFT JOIN DigitalRecordings AS dr 
        ON nml.fkDigitalRecordingCode = dr.RecordingCode
      ${whereClause}
    `;
    const [[{ total }]] = await db.query(countQuery);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT 
        nml.*,
        dr.PreservationStatus,
        dr.RecordingCode,
        dr.RecordingName,
        dr.fkEventCode
      FROM NewMediaLog AS nml
      LEFT JOIN DigitalRecordings AS dr 
        ON nml.fkDigitalRecordingCode = dr.RecordingCode
      ${whereClause}
      ORDER BY nml.MLUniqueID DESC
      LIMIT ? OFFSET ?
    `;
    const [rows] = await db.query(dataQuery, [limit, offset]);

    res.json({
      data: rows,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages
      }
    });
  } catch (err) {
    console.error("❌ API Error for /api/newmedialog/all-except-satsang:", err);
    res.status(500).json({ error: err.message });
  }
});

// --- Corrected Endpoint for "Satsang Extracted Clips" (Using your query) ---
app.get('/api/newmedialog/satsang-extracted-clips', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;

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

    // --- Count Query ---
    const countQuery = `
      SELECT COUNT(*) as total
      FROM NewMediaLog AS nml
      LEFT JOIN DigitalRecordings AS dr 
        ON nml.fkDigitalRecordingCode = dr.RecordingCode
      ${whereClause}
    `;
    const [[{ total }]] = await db.query(countQuery);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT 
        nml.*,
        dr.PreservationStatus,
        dr.RecordingCode,
        dr.RecordingName,
        dr.fkEventCode
      FROM NewMediaLog AS nml
      LEFT JOIN DigitalRecordings AS dr 
        ON nml.fkDigitalRecordingCode = dr.RecordingCode
      ${whereClause}
      ORDER BY nml.MLUniqueID DESC
      LIMIT ? OFFSET ?
    `;
    const [rows] = await db.query(dataQuery, [limit, offset]);

    res.json({
      data: rows,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages
      }
    });
  } catch (err) {
    console.error("❌ API Error for /api/newmedialog/satsang-extracted-clips:", err);
    res.status(500).json({ error: err.message });
  }
});


// --- Corrected Endpoint for "Satsang Category" (Using your query) ---
app.get('/api/newmedialog/satsang-category', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;

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

    // --- Count Query ---
    const countQuery = `
      SELECT COUNT(*) as total
      FROM NewMediaLog AS nml
      LEFT JOIN DigitalRecordings AS dr 
        ON nml.fkDigitalRecordingCode = dr.RecordingCode
      ${whereClause}
    `;
    const [[{ total }]] = await db.query(countQuery);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT 
        nml.*,
        dr.PreservationStatus,
        dr.RecordingCode,
        dr.RecordingName,
        dr.fkEventCode
      FROM NewMediaLog AS nml
      LEFT JOIN DigitalRecordings AS dr 
        ON nml.fkDigitalRecordingCode = dr.RecordingCode
      ${whereClause}
      ORDER BY nml.MLUniqueID DESC
      LIMIT ? OFFSET ?
    `;
    const [rows] = await db.query(dataQuery, [limit, offset]);

    res.json({
      data: rows,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages
      }
    });
  } catch (err) {
    console.error("❌ API Error for /api/newmedialog/satsang-category:", err);
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

    const filterableColumns = [
      'fkEventCode',
      'RecordingName',
      'RecordingCode',
      'NoOfFiles',
      'FilesizeInBytes',
        'fkDigitalMasterCategory',
        'fkMediaName',
        'BitRate',
        'AudioBitrate',
        'Filesize',
        'Duration',
        'AudioTotalDuration',
        'RecordingRemarks',
        'CounterError',
        'ReasonError',
        'QcRemarksCheckedOn',
        'PreservationStatus',
        'QcSevak',
        'MasterProductTitle',
        'Qcstatus',
        'LastModifiedTimestamp',
        'fkDistributionLabel',
        'SubmittedDate',
        'PresStatGuidDt',
        'InfoOnCassette',
        'Masterquality',
        'IsInformal',
        'AssociatedDR',
        'Dimension',
        'ProductionBucket',
        'DistributionDriveLink',
        'Teams'

    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      [ 'fkEventCode',
      'RecordingName',
      'RecordingCode',
      'NoOfFiles',
      'FilesizeInBytes',
        'fkDigitalMasterCategory',
        'fkMediaName',
        'BitRate',
        'AudioBitrate',
        'Filesize',
        'Duration',
        'AudioTotalDuration',
        'RecordingRemarks',
        'CounterError',
        'ReasonError',
        'QcRemarksCheckedOn',
        'PreservationStatus',
        'QcSevak',
        'MasterProductTitle',
        'Qcstatus',
        'LastModifiedTimestamp',
        'fkDistributionLabel',
        'SubmittedDate',
        'PresStatGuidDt',
        'InfoOnCassette',
        'Masterquality',
        'IsInformal',
        'AssociatedDR',
        'Dimension',
        'ProductionBucket',
        'DistributionDriveLink',
        'Teams'], // global search fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM DigitalRecordings ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT * 
      FROM DigitalRecordings 
      ${whereString} 
      ${orderByString}
      LIMIT ? OFFSET ?
    `;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages
      }
    });
  } catch (err) {
    console.error("❌ Database query error on /api/digitalrecording:", err);
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

    const filterableColumns = [
      'AUXID',
      'new_auxid',
      'AuxCode',
      'fkMLID',
      'NoOfFiles',
      'FilesizeBytes',
      'ProjFileSize',
      'AuxTopic',
      'NotesRemarks',
      'AuxLanguage',
        'AuxFileType',
        'GoogleDriveLink',
        'LastModifiedTimestamp',
        'LastModifiedBy',
        'ProjFileCode',
        'ProjFileName',
        'SRTLink',
        'CreatedOn',
        'CreatedBy',
        'ModifiedOn',
        'ModifiedBy'

      // ✅ Add more filterable columns here as needed
    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      [ 'AUXID',
      'new_auxid',
      'AuxCode',
      'fkMLID',
      'NoOfFiles',
      'FilesizeBytes',
      'ProjFileSize',
      'AuxTopic',
      'NotesRemarks',
      'AuxLanguage',
        'AuxFileType',
        'GoogleDriveLink',
        'LastModifiedTimestamp',
        'LastModifiedBy',
        'ProjFileCode',
        'ProjFileName',
        'SRTLink',
        'CreatedOn',
        'CreatedBy',
        'ModifiedOn',
        'ModifiedBy'], // global search fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM AuxFiles ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT * 
      FROM AuxFiles 
      ${whereString} 
      ${orderByString}
      LIMIT ? OFFSET ?
    `;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages
      }
    });
  } catch (err) {
    console.error("❌ Database query error on /api/auxfiles:", err);
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
// --- Get a single Event by EventCode ---
app.get('/api/events/:eventCode', async (req, res) => {
  const { eventCode } = req.params;
  try {
    const [results] = await db.query(
      'SELECT * FROM Events WHERE EventCode = ?',
      [eventCode]
    );

    if (!results || results.length === 0) {
      return res.status(404).json({ message: `Event with code ${eventCode} not found.` });
    }

    res.json(results[0]);
  } catch (err) {
    console.error("Database query error on single event:", err);
    res.status(500).json({ error: 'Database query failed' });
  }
});


// --- Get a single Digital Recording by RecordingCode ---
app.get('/api/digitalrecordings/:recordingCode', async (req, res) => {
  const { recordingCode } = req.params;
  try {
    const [results] = await db.query(
      'SELECT * FROM DigitalRecordings WHERE RecordingCode = ?',
      [recordingCode]
    );

    if (!results || results.length === 0) {
      return res.status(404).json({ message: `Digital Recording with code ${recordingCode} not found.` });
    }

    res.json(results[0]);
  } catch (err) {
    console.error("Database query error on single digital recording:", err);
    res.status(500).json({ error: 'Database query failed' });
  }
});


// --- Get a single New Media Log by MLUniqueID ---
app.get('/api/newmedialog/:mlid', async (req, res) => {
  const { mlid } = req.params;
  try {
    const [results] = await db.query(
      'SELECT * FROM NewMediaLog WHERE MLUniqueID = ?',
      [mlid]
    );

    if (!results || results.length === 0) {
      return res.status(404).json({ message: `Media Log with ID ${mlid} not found.` });
    }

    res.json(results[0]);
  } catch (err) {
    console.error("Database query error on single media log:", err);
    res.status(500).json({ error: 'Database query failed' });
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

// --- Send Invitation Endpoint ---
app.post("/api/send-invitation", async (req, res) => {
  const { email, role, teams, message, appLink } = req.body;

  if (!email) {
    return res.status(400).json({ message: "Recipient email is required." });
  }

  try {
    const transporter = await createTransporter();

    const mailOptions = {
      from: "your-email@gmail.com", // Your Gmail address
      to: email,
      subject: "You're Invited to Join Our App!",
      html: `
        <p>Hello,</p>
        <p>You have been invited to join our app as a <strong>${role}</strong>.</p>
        <p>Teams: ${teams.join(", ") || "None"}</p>
        <p>${message || ""}</p>
        <p><a href="${appLink}" target="_blank">Click here to join</a></p>
        <p>Best regards,<br>Your App Team</p>
      `,
    };

    await transporter.sendMail(mailOptions);

    res.status(200).json({ message: "Invitation sent successfully." });
  } catch (error) {
    console.error("Error sending email:", error);
    res.status(500).json({ message: "Failed to send invitation." });
  }
});

// OAuth2 Configuration

const createTransporter = async () => {
  const oauth2Client = new google.auth.OAuth2(
    process.env.CLIENT_ID,
    process.env.CLIENT_SECRET,
    process.env.REDIRECT_URI || "https://developers.google.com/oauthplayground"
  );

  oauth2Client.setCredentials({ refresh_token: process.env.REFRESH_TOKEN });

  const accessToken = await oauth2Client.getAccessToken();

  return nodemailer.createTransport({
    service: "Gmail",
    auth: {
      type: "OAuth2",
      user: process.env.EMAIL_USER, // Your Gmail address
      clientId: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      refreshToken: process.env.REFRESH_TOKEN,
      accessToken: accessToken.token,
    },
  });
};

// Google Sheets setup
const SHEET_ID = "1GaCTwU_LUFF2B9NbBVzenwRjrW8sPvUJMkKzDUOdme0";
const credentials = require("./service-account.json");

const auth = new google.auth.GoogleAuth({
  credentials,
  scopes: ["https://www.googleapis.com/auth/spreadsheets"],
});


// --- Helper Functions for Permissions ---

// Converts "Permissions" string from sheet (e.g., "Dashboard:read,write;Events:read") to an array of objects
const parsePermissions = (permissionString) => {
  if (!permissionString || typeof permissionString !== 'string') return [];
  try {
    return permissionString.split(';').map(p => {
      const [resource, actionsStr] = p.split(':');
      if (!resource || !actionsStr) return null;
      return { resource, actions: actionsStr.split(',') };
    }).filter(Boolean); // Filter out any null entries from bad formatting
  } catch (e) {
    console.error("Could not parse permissions string:", permissionString, e);
    return [];
  }
};

// Formats permissions array into a string for the sheet
const formatPermissions = (permissionsArray) => {
    if (!permissionsArray || permissionsArray.length === 0) return "";
    return permissionsArray.map(p => `${p.resource}:${p.actions.join(',')}`).join(';');
};


// ===================================================================================
// --- API ENDPOINTS ---
// ===================================================================================

// --- GET ALL USERS ---
app.get("/api/users", async (_req, res) => {
  try {
    const sheets = google.sheets({ version: "v4", auth: await auth.getClient() });
    const result = await sheets.spreadsheets.values.get({
      spreadsheetId: SHEET_ID,
      // Read all columns from A to K to include permissions
      range: "Sheet1!A2:K", 
    });

    const users = (result.data.values || []).map(row => ({
      id: row[0],
      name: row[1],
      email: row[2],
      role: row[3],
      status: row[4],
      joinedDate: row[5],
      lastActive: row[6],
      teams: row[7] ? row[7].split(",") : [],
      department: row[8],
      location: row[9],
      permissions: parsePermissions(row[10]) // Parse from Column K (index 10)
    }));
    res.json(users);
  } catch (err) {
    console.error("Error fetching users from Google Sheet:", err);
    res.status(500).json({ error: "Failed to fetch user data." });
  }
});

// --- ADD A NEW USER ---
app.post("/api/users", async (req, res) => {
  const { name, email, role, department, location, teams, permissions } = req.body;

  if (!name || !email || !role) {
    return res.status(400).json({ error: "Name, email, and role are required." });
  }

  try {
    const sheets = google.sheets({ version: "v4", auth: await auth.getClient() });

    const now = new Date();
    const newId = now.getTime().toString();
    const joinedDate = now.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
    const status = 'Active';
    const lastActive = now.toISOString();

    // Ensure teams and permissions are properly formatted
    const formattedTeams = Array.isArray(teams) ? teams : [];
    const formattedPermissions = permissions || [];

    // Order must match your Google Sheet columns: A, B, C... K
    const newRow = [
      newId,
      name,
      email,
      role,
      status,
      joinedDate,
      lastActive,
      formattedTeams.join(','), // Convert teams array to a comma-separated string
      department || '',
      location || '',
      formatPermissions(formattedPermissions), // Save the formatted string to Column K
    ];

    await sheets.spreadsheets.values.append({
      spreadsheetId: SHEET_ID,
      range: "Sheet1!A:K",
      valueInputOption: "USER_ENTERED",
      resource: {
        values: [newRow],
      },
    });

    const createdUser = {
      id: newId,
      name,
      email,
      role,
      status,
      joinedDate,
      lastActive,
      teams: formattedTeams,
      department,
      location,
      permissions: formattedPermissions,
    };

    res.status(201).json(createdUser);
  } catch (err) {
    console.error("Error adding user to Google Sheet:", err);
    res.status(500).json({ error: "Failed to add user." });
  }
});

// --- DELETE A USER ---
app.delete('/api/users/:id', async (req, res) => {
  const { id } = req.params;

  if (!id) {
    return res.status(400).json({ error: "User ID is required." });
  }

  try {
    const sheets = google.sheets({ version: "v4", auth: await auth.getClient() });

    // Get the sheet metadata to retrieve the sheetId dynamically
    const sheetMetadata = await sheets.spreadsheets.get({
      spreadsheetId: SHEET_ID,
    });
    const sheetId = sheetMetadata.data.sheets[0].properties.sheetId;

    // Fetch all rows in the first column (IDs)
    const getRowsResponse = await sheets.spreadsheets.values.get({
      spreadsheetId: SHEET_ID,
      range: 'Sheet1!A:A', 
    });

    const ids = getRowsResponse.data.values;
    if (!ids || ids.length === 0) {
      return res.status(404).json({ error: "Sheet is empty, user not found." });
    }

    // Skip the header row and find the user ID
    const rowIndexToDelete = ids.slice(1).findIndex(row => row[0] === id);

    if (rowIndexToDelete === -1) {
      return res.status(404).json({ error: "User not found." });
    }

    // Adjust the index to account for the skipped header row
    const adjustedRowIndex = rowIndexToDelete + 1;

    // Delete the row
    const batchUpdateRequest = {
      requests: [{
        deleteDimension: {
          range: {
            sheetId: sheetId,
            dimension: 'ROWS',
            startIndex: adjustedRowIndex,
            endIndex: adjustedRowIndex + 1,
          },
        },
      }],
    };

    await sheets.spreadsheets.batchUpdate({
      spreadsheetId: SHEET_ID,
      resource: batchUpdateRequest,
    });

    res.status(200).json({ message: 'User deleted successfully.' });
  } catch (err) {
    console.error("Error deleting user from Google Sheet:", err);
    res.status(500).json({ error: "Failed to delete user." });
  }
});

// --- UPDATE USER PERMISSIONS ---
app.put('/api/users/:id/permissions', async (req, res) => {
  const { id } = req.params;
  const { permissions } = req.body;

  if (!id || !permissions) {
    return res.status(400).json({ error: "User ID and permissions array are required." });
  }

  try {
    const sheets = google.sheets({ version: "v4", auth: await auth.getClient() });

    const getRowsResponse = await sheets.spreadsheets.values.get({
      spreadsheetId: SHEET_ID,
      range: 'Sheet1!A:A',
    });

    const ids = getRowsResponse.data.values;
    // We start searching from index 1 to skip the header row.
    const rowIndex = ids.slice(1).findIndex(row => row[0] === id); 

    if (rowIndex === -1) {
      return res.status(404).json({ error: "User not found." });
    }

    const permissionsString = formatPermissions(permissions);
    
    // rowIndex is 0-based from the data (A2 onwards), but sheet ranges are 1-based.
    // So, we need to add 2 to get the correct sheet row number (1 for header, 1 for 0-indexing).
    const sheetRowNumber = rowIndex + 2; 

    await sheets.spreadsheets.values.update({
      spreadsheetId: SHEET_ID,
      range: `Sheet1!K${sheetRowNumber}`, // Update cell in Column K for the correct row
      valueInputOption: 'USER_ENTERED',
      resource: {
        values: [[permissionsString]],
      },
    });

    res.status(200).json({ message: 'Permissions updated successfully.' });
  } catch (err) {
    console.error("Error updating permissions:", err);
    res.status(500).json({ error: "Failed to update permissions." });
  }
});




// Start server
const PORT = process.env.PORT || 3600;
app.listen(PORT, () => {
 
  console.log(`🚀 Server running on port ${PORT}`);
});