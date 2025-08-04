import React, { useState, useMemo } from 'react';

const MultiTabSpreadsheet = () => {
    const [activeTab, setActiveTab] = useState(() => {
        return parseInt(localStorage.getItem('costingModelActiveSpreadsheetTab')) || 0;
    });

    // Save active spreadsheet tab to localStorage when it changes
    React.useEffect(() => {
        localStorage.setItem('costingModelActiveSpreadsheetTab', activeTab.toString());
    }, [activeTab]);

    // All editable input data
    const [inputs, setInputs] = useState({
        fecTypes: {
            1: { cost: 82, description: "Basic" },
            2: { cost: 147, description: "Standard" },
            3: { cost: 207, description: "A/C" },
            4: { cost: 245, description: "Premium" }
        },
        staff: {
            JP_salary: 42181,
            AB_salary: 64797,
            allocations: {
                JP: { MX: 100, EM: 0, EMSupport: 0, EMProject: 0, EMIT: 0, EMStorage: 0 },
                AB: { MX: 35, EM: 25, EMSupport: 10, EMProject: 20, EMIT: 8, EMStorage: 2 }
            }
        },
        nonSalary: {
            annualMaintenance: { MX: 40000, EM: 56217, total: 96217 },
            liquidNitrogen: { MX: 5000, EM: 7500, total: 12500 },
            tools: { MX: 2500, EM: 5000, total: 7500 },
            consumables: { MX: 5000, EM: 18000, EMIT: 1700, total: 24700 },
            chemicals: { MX: 10000, total: 10000 },
            plasticware: { EM: 4500, total: 4500 },
            training: { MX: 1400, EM: 3000, total: 4400 },
            computing: { MX: 10000, EM: 5000, total: 15000 },
            licence: { MX: 4500, EM: 4500, total: 9000 },
            shipping: { EM: 5000, total: 5000 },
            repair: { EM: 6500, total: 6500 }
        },
        depreciation: {
            cryoEM: { replacementCost: 403011, lifespan: 10, currentAge: 0, allocation: 'EM' }
        },
        estates: {
            rooms: [
                { id: 'M3.036', size: 18.82, fecType: 3, MX: 40, EM: 60 },
                { id: 'M3.036A', size: 13.49, fecType: 3, MX: 100, EM: 0 },
                { id: 'M3.019', size: 9.00, fecType: 2, MX: 75, EM: 25 },
                { id: 'M3.032', size: 29.24, fecType: 3, MX: 40, EM: 10 },
                { id: 'M3.032C', size: 4.93, fecType: 2, MX: 50, EM: 50 },
                { id: 'M3.032B', size: 4.51, fecType: 2, MX: 50, EM: 50 }
            ]
        },
        usage: {
            MX: { capacity: 500, actual: 200, unit: 'plate' },
            EM: { capacity: 225, actual: 125, unit: 'day' },
            EMSupport: { capacity: 25, actual: 10, unit: 'day' },
            EMProject: { capacity: 10, actual: 5, unit: 'project' },
            EMIT: { capacity: 7, actual: 4, unit: 'month' },
            EMStorage: { capacity: 360, actual: 250, unit: 'TB year' }
        }
    });

    // Calculated values
    const calculated = useMemo(() => {
        // Staff cost calculations
        const staffCosts = {
            MX: (inputs.staff.JP_salary * inputs.staff.allocations.JP.MX / 100) +
                (inputs.staff.AB_salary * inputs.staff.allocations.AB.MX / 100),
            EM: (inputs.staff.AB_salary * inputs.staff.allocations.AB.EM / 100),
            EMSupport: (inputs.staff.AB_salary * inputs.staff.allocations.AB.EMSupport / 100),
            EMProject: (inputs.staff.AB_salary * inputs.staff.allocations.AB.EMProject / 100),
            EMIT: (inputs.staff.AB_salary * inputs.staff.allocations.AB.EMIT / 100),
            EMStorage: (inputs.staff.AB_salary * inputs.staff.allocations.AB.EMStorage / 100)
        };

        // Non-salary totals - calculate dynamically from inputs.nonSalary
        const nonSalaryCosts = {
            MX: 0,
            EM: 0,
            EMSupport: 0,
            EMProject: 0,
            EMIT: 0,
            EMStorage: 0
        };

        // Sum up all non-salary costs by service
        Object.values(inputs.nonSalary).forEach(item => {
            nonSalaryCosts.MX += item.MX || 0;
            nonSalaryCosts.EM += item.EM || 0;
            nonSalaryCosts.EMSupport += item.EMSupport || 0;
            nonSalaryCosts.EMProject += item.EMProject || 0;
            nonSalaryCosts.EMIT += item.EMIT || 0;
            nonSalaryCosts.EMStorage += item.EMStorage || 0;
        });

        // Depreciation calculations
        const depreciation = {
            MX: 0,
            EM: inputs.depreciation.cryoEM.replacementCost / inputs.depreciation.cryoEM.lifespan,
            EMSupport: 0,
            EMProject: 0,
            EMIT: 0,
            EMStorage: 0
        };

        // Estates calculations
        const estatesCosts = inputs.estates.rooms.reduce((acc, room) => {
            const costPerM2 = inputs.fecTypes[room.fecType].cost;
            const totalRoomCost = room.size * costPerM2;

            acc.MX += totalRoomCost * (room.MX / 100);
            acc.EM += totalRoomCost * (room.EM / 100);
            return acc;
        }, { MX: 0, EM: 0, EMSupport: 0, EMProject: 0, EMIT: 0, EMStorage: 0 });

        // Main summary
        const services = ['MX', 'EM', 'EMSupport', 'EMProject', 'EMIT', 'EMStorage'];
        const mainSummary = services.map(service => ({
            service,
            salaryCosts: Math.round(staffCosts[service] || 0),
            nonSalaryCosts: nonSalaryCosts[service] || 0,
            estatesCosts: Math.round(estatesCosts[service] || 0),
            depreciationCosts: Math.round(depreciation[service] || 0),
            totalCosts: Math.round((staffCosts[service] || 0) + (nonSalaryCosts[service] || 0) +
                (estatesCosts[service] || 0) + (depreciation[service] || 0)),
            usage: inputs.usage[service] || { capacity: 0, actual: 0, unit: '' }
        }));

        // Calculate rates for all services
        const rates = {};
        services.forEach(service => {
            const usage = inputs.usage[service];
            if (!usage || usage.actual === 0) {
                rates[service] = { excludingSalaries: 0, directCosts: 0, excludingEstates: 0, excludingDepn: 0, includingAll: 0 };
            } else {
                const salaryCosts = staffCosts[service] || 0;
                const nonSalary = nonSalaryCosts[service] || 0;
                const estates = estatesCosts[service] || 0;
                const depn = depreciation[service] || 0;

                rates[service] = {
                    excludingSalaries: (nonSalary + estates + depn) / usage.actual,
                    directCosts: (salaryCosts + nonSalary + estates + depn) / usage.actual,
                    excludingEstates: (salaryCosts + nonSalary + depn) / usage.actual,
                    excludingDepn: (salaryCosts + nonSalary + estates) / usage.actual,
                    includingAll: (salaryCosts + nonSalary + estates + depn) / usage.actual
                };
            }
        });

        return { staffCosts, nonSalaryCosts, depreciation, estatesCosts, mainSummary, rates };
    }, [inputs]);

    const updateInputs = (section, data) => {
        setInputs(prev => ({ ...prev, [section]: data }));
    };

    const tabs = [
        { name: 'Main Summary', id: 'main' },
        { name: 'Staff Costs', id: 'staff' },
        { name: 'Non-Salary Costs', id: 'nonsalary' },
        { name: 'Depreciation', id: 'depreciation' },
        { name: 'Estates Cost', id: 'estates' }
    ];

    // SIMPLIFIED EditableCell - no formatting nonsense
    const EditableCell = ({ value, onChange, type = "number" }) => {
        return (
            <input
                type={type === "number" ? "number" : "text"}
                value={value || ''}
                onChange={(e) => {
                    const val = type === "number" ? (parseFloat(e.target.value) || 0) : e.target.value;
                    onChange(val);
                }}
                style={{
                    width: '100%',
                    border: '1px solid #ccc',
                    padding: '4px',
                    textAlign: type === "number" ? 'right' : 'left',
                    minWidth: '80px'
                }}
            />
        );
    };

    const renderMainSummary = () => {
        return (
            <div>
                <h3>Main Costs Summary</h3>
                <table style={{ borderCollapse: 'collapse', width: '100%', fontSize: '12px' }}>
                    <thead>
                    <tr style={{ backgroundColor: '#f0f0f0' }}>
                        <th style={{ border: '1px solid #ccc', padding: '4px' }}>Service</th>
                        <th style={{ border: '1px solid #ccc', padding: '4px' }}>Salary Costs</th>
                        <th style={{ border: '1px solid #ccc', padding: '4px' }}>Non-Salary</th>
                        <th style={{ border: '1px solid #ccc', padding: '4px' }}>Annual Estates</th>
                        <th style={{ border: '1px solid #ccc', padding: '4px' }}>Depn.</th>
                        <th style={{ border: '1px solid #ccc', padding: '4px' }}>Total Costs</th>
                        <th style={{ border: '1px solid #ccc', padding: '4px' }}>Charge Unit</th>
                        <th style={{ border: '1px solid #ccc', padding: '4px' }}>Annual Usage</th>
                        <th style={{ border: '1px solid #ccc', padding: '4px' }}>Annual Capacity</th>
                        <th style={{ border: '1px solid #ccc', padding: '4px' }}>Rate Excluding Salaries</th>
                        <th style={{ border: '1px solid #ccc', padding: '4px' }}>Rate Direct Costs Only</th>
                        <th style={{ border: '1px solid #ccc', padding: '4px' }}>Rate Excluding Estates</th>
                        <th style={{ border: '1px solid #ccc', padding: '4px' }}>Rate Excluding Depn.</th>
                        <th style={{ border: '1px solid #ccc', padding: '4px' }}>Rate Including All Costs</th>
                        <th style={{ border: '1px solid #ccc', padding: '4px' }}>Implied Income</th>
                    </tr>
                    </thead>
                    <tbody>
                    {calculated.mainSummary.map(item => {
                        // Get the current usage values directly from inputs to ensure real-time updates
                        const currentUsage = inputs.usage[item.service] || { capacity: 0, actual: 0, unit: '' };
                        const serviceRates = calculated.rates[item.service] || { excludingSalaries: 0, directCosts: 0, excludingEstates: 0, excludingDepn: 0, includingAll: 0 };
                        const impliedIncome = serviceRates.includingAll * currentUsage.actual;

                        return (
                            <tr key={item.service}>
                                <td style={{ border: '1px solid #ccc', padding: '4px' }}>{item.service}</td>
                                <td style={{ border: '1px solid #ccc', padding: '4px', textAlign: 'right' }}>{item.salaryCosts}</td>
                                <td style={{ border: '1px solid #ccc', padding: '4px', textAlign: 'right' }}>{item.nonSalaryCosts}</td>
                                <td style={{ border: '1px solid #ccc', padding: '4px', textAlign: 'right' }}>{item.estatesCosts}</td>
                                <td style={{ border: '1px solid #ccc', padding: '4px', textAlign: 'right' }}>{item.depreciationCosts}</td>
                                <td style={{ border: '1px solid #ccc', padding: '4px', textAlign: 'right' }}>{item.totalCosts}</td>
                                <td style={{ border: '1px solid #ccc', padding: '4px' }}>{currentUsage.unit}</td>
                                <td style={{ border: '1px solid #ccc', padding: '4px' }}>
                                    <EditableCell
                                        value={currentUsage.actual}
                                        onChange={(val) => updateInputs('usage', {
                                            ...inputs.usage,
                                            [item.service]: { ...inputs.usage[item.service], actual: val }
                                        })}
                                    />
                                </td>
                                <td style={{ border: '1px solid #ccc', padding: '4px' }}>
                                    <EditableCell
                                        value={currentUsage.capacity}
                                        onChange={(val) => updateInputs('usage', {
                                            ...inputs.usage,
                                            [item.service]: { ...inputs.usage[item.service], capacity: val }
                                        })}
                                    />
                                </td>
                                <td style={{ border: '1px solid #ccc', padding: '4px', textAlign: 'right' }}>{serviceRates.excludingSalaries.toFixed(2)}</td>
                                <td style={{ border: '1px solid #ccc', padding: '4px', textAlign: 'right' }}>{serviceRates.directCosts.toFixed(2)}</td>
                                <td style={{ border: '1px solid #ccc', padding: '4px', textAlign: 'right' }}>{serviceRates.excludingEstates.toFixed(2)}</td>
                                <td style={{ border: '1px solid #ccc', padding: '4px', textAlign: 'right' }}>{serviceRates.excludingDepn.toFixed(2)}</td>
                                <td style={{ border: '1px solid #ccc', padding: '4px', textAlign: 'right' }}>{serviceRates.includingAll.toFixed(2)}</td>
                                <td style={{ border: '1px solid #ccc', padding: '4px', textAlign: 'right' }}>{Math.round(impliedIncome)}</td>
                            </tr>
                        );
                    })}
                    </tbody>
                </table>
            </div>
        );
    };

    const renderStaffCosts = () => (
        <div>
            <h3>Staff Costs</h3>
            <table style={{ borderCollapse: 'collapse', width: '100%' }}>
                <thead>
                <tr style={{ backgroundColor: '#f0f0f0' }}>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>Staff</th>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>Total Salary</th>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>MX %</th>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>EM %</th>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>EM Support %</th>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>EM Project %</th>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>EM IT %</th>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>EM Storage %</th>
                </tr>
                </thead>
                <tbody>
                <tr>
                    <td style={{ border: '1px solid #ccc', padding: '8px' }}>JP (grade E)</td>
                    <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                        <EditableCell
                            value={inputs.staff.JP_salary}
                            onChange={(val) => updateInputs('staff', { ...inputs.staff, JP_salary: val })}
                        />
                    </td>
                    <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                        <EditableCell
                            value={inputs.staff.allocations.JP.MX}
                            onChange={(val) => updateInputs('staff', {
                                ...inputs.staff,
                                allocations: {
                                    ...inputs.staff.allocations,
                                    JP: { ...inputs.staff.allocations.JP, MX: val }
                                }
                            })}
                        />
                    </td>
                    <td style={{ border: '1px solid #ccc', padding: '8px' }}>{inputs.staff.allocations.JP.EM}</td>
                    <td style={{ border: '1px solid #ccc', padding: '8px' }}>{inputs.staff.allocations.JP.EMSupport}</td>
                    <td style={{ border: '1px solid #ccc', padding: '8px' }}>{inputs.staff.allocations.JP.EMProject}</td>
                    <td style={{ border: '1px solid #ccc', padding: '8px' }}>{inputs.staff.allocations.JP.EMIT}</td>
                    <td style={{ border: '1px solid #ccc', padding: '8px' }}>{inputs.staff.allocations.JP.EMStorage}</td>
                </tr>
                <tr>
                    <td style={{ border: '1px solid #ccc', padding: '8px' }}>AB (grade G)</td>
                    <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                        <EditableCell
                            value={inputs.staff.AB_salary}
                            onChange={(val) => updateInputs('staff', { ...inputs.staff, AB_salary: val })}
                        />
                    </td>
                    <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                        <EditableCell
                            value={inputs.staff.allocations.AB.MX}
                            onChange={(val) => updateInputs('staff', {
                                ...inputs.staff,
                                allocations: {
                                    ...inputs.staff.allocations,
                                    AB: { ...inputs.staff.allocations.AB, MX: val }
                                }
                            })}
                        />
                    </td>
                    <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                        <EditableCell
                            value={inputs.staff.allocations.AB.EM}
                            onChange={(val) => updateInputs('staff', {
                                ...inputs.staff,
                                allocations: {
                                    ...inputs.staff.allocations,
                                    AB: { ...inputs.staff.allocations.AB, EM: val }
                                }
                            })}
                        />
                    </td>
                    <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                        <EditableCell
                            value={inputs.staff.allocations.AB.EMSupport}
                            onChange={(val) => updateInputs('staff', {
                                ...inputs.staff,
                                allocations: {
                                    ...inputs.staff.allocations,
                                    AB: { ...inputs.staff.allocations.AB, EMSupport: val }
                                }
                            })}
                        />
                    </td>
                    <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                        <EditableCell
                            value={inputs.staff.allocations.AB.EMProject}
                            onChange={(val) => updateInputs('staff', {
                                ...inputs.staff,
                                allocations: {
                                    ...inputs.staff.allocations,
                                    AB: { ...inputs.staff.allocations.AB, EMProject: val }
                                }
                            })}
                        />
                    </td>
                    <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                        <EditableCell
                            value={inputs.staff.allocations.AB.EMIT}
                            onChange={(val) => updateInputs('staff', {
                                ...inputs.staff,
                                allocations: {
                                    ...inputs.staff.allocations,
                                    AB: { ...inputs.staff.allocations.AB, EMIT: val }
                                }
                            })}
                        />
                    </td>
                    <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                        <EditableCell
                            value={inputs.staff.allocations.AB.EMStorage}
                            onChange={(val) => updateInputs('staff', {
                                ...inputs.staff,
                                allocations: {
                                    ...inputs.staff.allocations,
                                    AB: { ...inputs.staff.allocations.AB, EMStorage: val }
                                }
                            })}
                        />
                    </td>
                </tr>
                </tbody>
            </table>
        </div>
    );

    const renderNonSalaryCosts = () => (
        <div>
            <h3>Non-Salary Costs</h3>
            <table style={{ borderCollapse: 'collapse', width: '100%' }}>
                <thead>
                <tr style={{ backgroundColor: '#f0f0f0' }}>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>Items</th>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>MX</th>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>EM</th>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>EM Support</th>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>EM Project</th>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>EM IT</th>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>EM Storage</th>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>Total</th>
                </tr>
                </thead>
                <tbody>
                {Object.entries(inputs.nonSalary).map(([item, costs]) => (
                    <tr key={item}>
                        <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                            <EditableCell
                                type="text"
                                value={item}
                                onChange={(val) => {
                                    // Create new nonSalary object with updated key
                                    const newNonSalary = { ...inputs.nonSalary };
                                    delete newNonSalary[item];
                                    newNonSalary[val] = costs;
                                    updateInputs('nonSalary', newNonSalary);
                                }}
                            />
                        </td>
                        <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                            <EditableCell
                                value={costs.MX || 0}
                                onChange={(val) => updateInputs('nonSalary', {
                                    ...inputs.nonSalary,
                                    [item]: { ...costs, MX: val }
                                })}
                            />
                        </td>
                        <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                            <EditableCell
                                value={costs.EM || 0}
                                onChange={(val) => updateInputs('nonSalary', {
                                    ...inputs.nonSalary,
                                    [item]: { ...costs, EM: val }
                                })}
                            />
                        </td>
                        <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                            <EditableCell
                                value={costs.EMSupport || 0}
                                onChange={(val) => updateInputs('nonSalary', {
                                    ...inputs.nonSalary,
                                    [item]: { ...costs, EMSupport: val }
                                })}
                            />
                        </td>
                        <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                            <EditableCell
                                value={costs.EMProject || 0}
                                onChange={(val) => updateInputs('nonSalary', {
                                    ...inputs.nonSalary,
                                    [item]: { ...costs, EMProject: val }
                                })}
                            />
                        </td>
                        <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                            <EditableCell
                                value={costs.EMIT || 0}
                                onChange={(val) => updateInputs('nonSalary', {
                                    ...inputs.nonSalary,
                                    [item]: { ...costs, EMIT: val }
                                })}
                            />
                        </td>
                        <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                            <EditableCell
                                value={costs.EMStorage || 0}
                                onChange={(val) => updateInputs('nonSalary', {
                                    ...inputs.nonSalary,
                                    [item]: { ...costs, EMStorage: val }
                                })}
                            />
                        </td>
                        <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                            <EditableCell
                                value={costs.total}
                                onChange={(val) => updateInputs('nonSalary', {
                                    ...inputs.nonSalary,
                                    [item]: { ...costs, total: val }
                                })}
                            />
                        </td>
                    </tr>
                ))}
                </tbody>
            </table>
        </div>
    );

    const renderDepreciation = () => (
        <div>
            <h3>Depreciation</h3>
            <table style={{ borderCollapse: 'collapse', width: '100%' }}>
                <thead>
                <tr style={{ backgroundColor: '#f0f0f0' }}>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>Component</th>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>Replacement Cost</th>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>Lifespan</th>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>Current Age</th>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>Annual Depreciation</th>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>Allocated To</th>
                </tr>
                </thead>
                <tbody>
                {Object.entries(inputs.depreciation).map(([item, data]) => (
                    <tr key={item}>
                        <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                            <EditableCell
                                type="text"
                                value={item}
                                onChange={(val) => {
                                    // Create new depreciation object with updated key
                                    const newDepreciation = { ...inputs.depreciation };
                                    delete newDepreciation[item];
                                    newDepreciation[val] = data;
                                    updateInputs('depreciation', newDepreciation);
                                }}
                            />
                        </td>
                        <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                            <EditableCell
                                value={data.replacementCost}
                                onChange={(val) => updateInputs('depreciation', {
                                    ...inputs.depreciation,
                                    [item]: { ...data, replacementCost: val }
                                })}
                            />
                        </td>
                        <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                            <EditableCell
                                value={data.lifespan}
                                onChange={(val) => updateInputs('depreciation', {
                                    ...inputs.depreciation,
                                    [item]: { ...data, lifespan: val }
                                })}
                            />
                        </td>
                        <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                            <EditableCell
                                value={data.currentAge}
                                onChange={(val) => updateInputs('depreciation', {
                                    ...inputs.depreciation,
                                    [item]: { ...data, currentAge: val }
                                })}
                            />
                        </td>
                        <td style={{ border: '1px solid #ccc', padding: '8px', textAlign: 'right' }}>
                            {Math.round(data.replacementCost / data.lifespan)}
                        </td>
                        <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                            <EditableCell
                                type="text"
                                value={data.allocation}
                                onChange={(val) => updateInputs('depreciation', {
                                    ...inputs.depreciation,
                                    [item]: { ...data, allocation: val }
                                })}
                            />
                        </td>
                    </tr>
                ))}
                </tbody>
            </table>
        </div>
    );

    const renderEstates = () => (
        <div>
            <h3>Estates Cost</h3>

            {/* fEC Types Table */}
            <div style={{ marginBottom: '30px' }}>
                <h4>fEC Types</h4>
                <table style={{ borderCollapse: 'collapse', width: '300px' }}>
                    <thead>
                    <tr style={{ backgroundColor: '#f0f0f0' }}>
                        <th style={{ border: '1px solid #ccc', padding: '8px' }}>Type</th>
                        <th style={{ border: '1px solid #ccc', padding: '8px' }}>Cost per m²</th>
                        <th style={{ border: '1px solid #ccc', padding: '8px' }}>Description</th>
                    </tr>
                    </thead>
                    <tbody>
                    {Object.entries(inputs.fecTypes).map(([typeId, data]) => (
                        <tr key={typeId}>
                            <td style={{ border: '1px solid #ccc', padding: '8px', textAlign: 'center' }}>{typeId}</td>
                            <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                                <EditableCell
                                    value={data.cost}
                                    onChange={(val) => updateInputs('fecTypes', {
                                        ...inputs.fecTypes,
                                        [typeId]: { ...data, cost: val }
                                    })}
                                />
                            </td>
                            <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                                <EditableCell
                                    type="text"
                                    value={data.description}
                                    onChange={(val) => updateInputs('fecTypes', {
                                        ...inputs.fecTypes,
                                        [typeId]: { ...data, description: val }
                                    })}
                                />
                            </td>
                        </tr>
                    ))}
                    </tbody>
                </table>
            </div>

            {/* Rooms Table */}
            <h4>Room Allocations</h4>
            <table style={{ borderCollapse: 'collapse', width: '100%' }}>
                <thead>
                <tr style={{ backgroundColor: '#f0f0f0' }}>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>Room</th>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>Size (m²)</th>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>fEC Type</th>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>Cost per m²</th>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>Total Cost</th>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>MX %</th>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>EM %</th>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>MX Cost</th>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>EM Cost</th>
                </tr>
                </thead>
                <tbody>
                {inputs.estates.rooms.map((room, index) => {
                    const costPerM2 = inputs.fecTypes[room.fecType].cost;
                    const totalCost = room.size * costPerM2;
                    const mxCost = totalCost * (room.MX / 100);
                    const emCost = totalCost * (room.EM / 100);

                    return (
                        <tr key={room.id}>
                            <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                                <EditableCell
                                    type="text"
                                    value={room.id}
                                    onChange={(val) => {
                                        const newRooms = [...inputs.estates.rooms];
                                        newRooms[index] = { ...room, id: val };
                                        updateInputs('estates', { ...inputs.estates, rooms: newRooms });
                                    }}
                                />
                            </td>
                            <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                                <EditableCell
                                    value={room.size}
                                    onChange={(val) => {
                                        const newRooms = [...inputs.estates.rooms];
                                        newRooms[index] = { ...room, size: val };
                                        updateInputs('estates', { ...inputs.estates, rooms: newRooms });
                                    }}
                                />
                            </td>
                            <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                                <select
                                    value={room.fecType}
                                    onChange={(e) => {
                                        const newRooms = [...inputs.estates.rooms];
                                        newRooms[index] = { ...room, fecType: parseInt(e.target.value) };
                                        updateInputs('estates', { ...inputs.estates, rooms: newRooms });
                                    }}
                                    style={{ width: '60px' }}
                                >
                                    {Object.keys(inputs.fecTypes).map(type => (
                                        <option key={type} value={type}>{type}</option>
                                    ))}
                                </select>
                            </td>
                            <td style={{ border: '1px solid #ccc', padding: '8px', textAlign: 'right' }}>{costPerM2}</td>
                            <td style={{ border: '1px solid #ccc', padding: '8px', textAlign: 'right' }}>{Math.round(totalCost)}</td>
                            <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                                <EditableCell
                                    value={room.MX}
                                    onChange={(val) => {
                                        const newRooms = [...inputs.estates.rooms];
                                        newRooms[index] = { ...room, MX: val };
                                        updateInputs('estates', { ...inputs.estates, rooms: newRooms });
                                    }}
                                />
                            </td>
                            <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                                <EditableCell
                                    value={room.EM}
                                    onChange={(val) => {
                                        const newRooms = [...inputs.estates.rooms];
                                        newRooms[index] = { ...room, EM: val };
                                        updateInputs('estates', { ...inputs.estates, rooms: newRooms });
                                    }}
                                />
                            </td>
                            <td style={{ border: '1px solid #ccc', padding: '8px', textAlign: 'right' }}>{Math.round(mxCost)}</td>
                            <td style={{ border: '1px solid #ccc', padding: '8px', textAlign: 'right' }}>{Math.round(emCost)}</td>
                        </tr>
                    );
                })}
                </tbody>
            </table>
        </div>
    );

    const renderContent = () => {
        switch (activeTab) {
            case 0: return renderMainSummary();
            case 1: return renderStaffCosts();
            case 2: return renderNonSalaryCosts();
            case 3: return renderDepreciation();
            case 4: return renderEstates();
            default: return renderMainSummary();
        }
    };

    return (
        <div style={{ fontFamily: 'Arial, sans-serif', padding: '20px' }}>
            {/* Tab Navigation */}
            <div style={{ marginBottom: '20px' }}>
                {tabs.map((tab, index) => (
                    <button
                        key={tab.id}
                        onClick={() => setActiveTab(index)}
                        style={{
                            padding: '10px 20px',
                            marginRight: '5px',
                            backgroundColor: activeTab === index ? '#007bff' : '#f8f9fa',
                            color: activeTab === index ? 'white' : 'black',
                            border: '1px solid #ccc',
                            cursor: 'pointer',
                            borderRadius: '4px 4px 0 0'
                        }}
                    >
                        {tab.name}
                    </button>
                ))}
            </div>

            {/* Content Area */}
            <div style={{
                border: '1px solid #ccc',
                padding: '20px',
                backgroundColor: 'white',
                minHeight: '500px'
            }}>
                {renderContent()}
            </div>
        </div>
    );
};

const FecTypesTable = () => {
    const [fecTypes, setFecTypes] = useState({
        1: { cost: 82, description: "Basic" },
        2: { cost: 147, description: "Standard" },
        3: { cost: 207, description: "A/C" },
        4: { cost: 245, description: "Premium" }
    });

    const updateFecType = (typeId, newCost) => {
        setFecTypes(prev => ({
            ...prev,
            [typeId]: { ...prev[typeId], cost: newCost }
        }));
    };

    const updateDescription = (typeId, newDesc) => {
        setFecTypes(prev => ({
            ...prev,
            [typeId]: { ...prev[typeId], description: newDesc }
        }));
    };

    return (
        <div style={{ padding: '20px', fontFamily: 'Arial, sans-serif' }}>
            <h3>fEC Types Lookup Table</h3>
            <table style={{ borderCollapse: 'collapse', width: '100%' }}>
                <thead>
                <tr style={{ backgroundColor: '#f0f0f0' }}>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>Type</th>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>Cost per m²</th>
                    <th style={{ border: '1px solid #ccc', padding: '8px' }}>Description</th>
                </tr>
                </thead>
                <tbody>
                {Object.entries(fecTypes).map(([typeId, data]) => (
                    <tr key={typeId}>
                        <td style={{ border: '1px solid #ccc', padding: '8px', textAlign: 'center' }}>
                            {typeId}
                        </td>
                        <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                            <input
                                type="number"
                                value={data.cost}
                                onChange={(e) => updateFecType(typeId, parseInt(e.target.value) || 0)}
                                style={{ width: '100%', border: 'none', padding: '4px' }}
                            />
                        </td>
                        <td style={{ border: '1px solid #ccc', padding: '8px' }}>
                            <input
                                type="text"
                                value={data.description}
                                onChange={(e) => updateDescription(typeId, e.target.value)}
                                style={{ width: '100%', border: 'none', padding: '4px' }}
                            />
                        </td>
                    </tr>
                ))}
                </tbody>
            </table>

            <div style={{ marginTop: '20px', padding: '10px', backgroundColor: '#f9f9f9' }}>
                <h4>Current Values:</h4>
                <pre>{JSON.stringify(fecTypes, null, 2)}</pre>
            </div>
        </div>
    );
};

function CostingModelTab({ userData }) {
    const [activeCostingTab, setActiveCostingTab] = useState(() => {
        return localStorage.getItem('costingModelActiveFinancialYear') || '2025-2026';
    });
    const [financialYears, setFinancialYears] = useState(() => {
        const savedYears = localStorage.getItem('costingModelFinancialYears');
        return savedYears ? JSON.parse(savedYears) : ['2025-2026'];
    });

    // Save active financial year tab to localStorage when it changes
    React.useEffect(() => {
        localStorage.setItem('costingModelActiveFinancialYear', activeCostingTab);
    }, [activeCostingTab]);

    // Save financial years to localStorage when they change
    React.useEffect(() => {
        localStorage.setItem('costingModelFinancialYears', JSON.stringify(financialYears));
    }, [financialYears]);

    const addNewFinancialYear = () => {
        // Get the latest year from the last tab
        const latestTab = financialYears[financialYears.length - 1];
        const latestStartYear = parseInt(latestTab.split('-')[0]);
        const newStartYear = latestStartYear + 1;
        const newEndYear = newStartYear + 1;
        const newYearTab = `${newStartYear}-${newEndYear}`;

        setFinancialYears([...financialYears, newYearTab]);
        setActiveCostingTab(newYearTab);
    };

    return (
        <div>
            <div style={{ display: 'flex', borderBottom: '1px solid #dee2e6', marginBottom: '20px', backgroundColor: '#f8f9fa' }}>
                {financialYears.map((year) => (
                    <div
                        key={year}
                        onClick={() => setActiveCostingTab(year)}
                        style={{
                            padding: '10px 20px',
                            cursor: 'pointer',
                            backgroundColor: activeCostingTab === year ? '#ffffff' : 'transparent',
                            borderBottom: activeCostingTab === year ? '2px solid #007bff' : 'none',
                            fontWeight: activeCostingTab === year ? 'bold' : 'normal',
                            border: activeCostingTab === year ? '1px solid #dee2e6' : 'none',
                            borderBottom: activeCostingTab === year ? 'none' : '1px solid #dee2e6'
                        }}
                    >
                        {year}
                    </div>
                ))}
                <div
                    onClick={addNewFinancialYear}
                    style={{
                        padding: '10px 15px',
                        cursor: 'pointer',
                        backgroundColor: 'transparent',
                        border: '1px solid #dee2e6',
                        borderBottom: '1px solid #dee2e6',
                        color: '#007bff',
                        fontWeight: 'bold',
                        fontSize: '16px',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center'
                    }}
                    title="Add new financial year"
                >
                    +
                </div>
            </div>
            <div style={{ backgroundColor: '#ffffff', padding: '20px', border: '1px solid #dee2e6', borderRadius: '0 0 4px 4px' }}>
                {financialYears.map((year) => (
                    activeCostingTab === year && (
                        <div key={year}>
                            <h4>Financial Year: {year}</h4>
                            {year === '2025-2026' && <MultiTabSpreadsheet />}
                        </div>
                    )
                ))}
            </div>
        </div>
    );
}

export default CostingModelTab;