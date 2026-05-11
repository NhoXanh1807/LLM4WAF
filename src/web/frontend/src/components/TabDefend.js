
import React, { useEffect, useRef, useState } from 'react';
import { Services } from '../services';
import PayloadResultsTable from './PayloadResultsTable';

const ACCEPTED_RULE_FILE_TYPES = '.txt,.conf,.cfg,.cnf,.config,.rules,.rule,.json,.jsonl,.ndjson,.yaml,.yml,.ini,.toml,.xml';

const splitTextareaLines = (value) => String(value || '')
    .split(/\r?\n/)
    .map(item => item.trim())
    .filter(Boolean);

const cardShell = darkMode => (
    darkMode
        ? 'rounded-2xl border border-gray-700 bg-gray-900/70 shadow-[0_20px_60px_rgba(0,0,0,0.25)]'
        : 'rounded-2xl border border-slate-200 bg-white shadow-[0_20px_60px_rgba(15,23,42,0.08)]'
);

const textareaShell = darkMode => (
    darkMode
        ? 'w-full rounded-xl border border-gray-700 bg-gray-950 text-green-300 placeholder:text-gray-500'
        : 'w-full rounded-xl border border-slate-300 bg-slate-50 text-slate-800 placeholder:text-slate-400'
);

const badgeShell = (darkMode, tone) => {
    const styles = {
        blue: darkMode ? 'bg-cyan-950/70 text-cyan-300' : 'bg-cyan-100 text-cyan-700',
        amber: darkMode ? 'bg-amber-950/70 text-amber-300' : 'bg-amber-100 text-amber-700',
        red: darkMode ? 'bg-red-950/70 text-red-300' : 'bg-red-100 text-red-700',
        green: darkMode ? 'bg-emerald-950/70 text-emerald-300' : 'bg-emerald-100 text-emerald-700',
        slate: darkMode ? 'bg-gray-800 text-gray-300' : 'bg-slate-100 text-slate-700',
        violet: darkMode ? 'bg-violet-950/70 text-violet-300' : 'bg-violet-100 text-violet-700',
    };

    return `inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold ${styles[tone]}`;
};

const infoValueShell = (darkMode, tone = 'blue') => {
    const styles = {
        blue: darkMode
            ? 'border-cyan-800/80 bg-cyan-950/50 text-cyan-200'
            : 'border-cyan-200 bg-cyan-50 text-cyan-800',
        violet: darkMode
            ? 'border-violet-800/80 bg-violet-950/50 text-violet-200'
            : 'border-violet-200 bg-violet-50 text-violet-800',
        amber: darkMode
            ? 'border-amber-800/80 bg-amber-950/50 text-amber-200'
            : 'border-amber-200 bg-amber-50 text-amber-800',
        slate: darkMode
            ? 'border-gray-700 bg-gray-800/80 text-gray-200'
            : 'border-slate-200 bg-slate-100 text-slate-700',
    };

    return `flex min-h-[44px] items-center rounded-2xl border px-4 text-sm font-bold shadow-sm ${styles[tone]}`;
};

const loadingButtonClass = 'bg-gradient-to-r from-yellow-400 to-yellow-600';

const getActionButtonClass = (loading, enabledClassName) => (
    loading
        ? loadingButtonClass
        : `${enabledClassName} disabled:from-gray-400 disabled:via-gray-400 disabled:to-gray-500`
);

const AfterStepNotice = ({ darkMode, tone, message, linkText, onClick }) => {
    const styles = {
        cyan: darkMode ? 'border-cyan-900 text-cyan-200/80' : 'border-cyan-300 text-cyan-800',
        violet: darkMode ? 'border-violet-900 text-violet-200/80' : 'border-violet-300 text-violet-800',
        emerald: darkMode ? 'border-emerald-900 text-emerald-200/80' : 'border-emerald-300 text-emerald-800',
        amber: darkMode ? 'border-amber-900 text-amber-200/80' : 'border-amber-300 text-amber-800',
    };

    return (
        <div className={`rounded-xl border border-dashed p-5 text-sm ${styles[tone]}`}>
            <span>
                {message}{' '}
                {linkText && onClick && (
                    <button
                        type="button"
                        onClick={onClick}
                        className={`font-semibold underline underline-offset-2 transition-all duration-200 ${darkMode ? 'text-white hover:text-gray-200' : 'text-slate-900 hover:text-slate-700'}`}
                    >
                        {linkText}
                    </button>
                )}
            </span>
        </div>
    );
};

const ExistingRulesDetectedNotice = ({ darkMode, count, onClick }) => (
    <div className="rounded-xl border border-dashed p-5 text-sm border-cyan-300 text-cyan-800 dark:border-cyan-900 dark:text-cyan-200/80">
        <button
            type="button"
            onClick={onClick}
            className={`font-semibold underline underline-offset-2 transition-all duration-200 ${darkMode ? 'text-white hover:text-gray-200' : 'text-slate-900 hover:text-slate-700'}`}
        >
            Existing rules detected ({count})
        </button>
    </div>
);

const StepSection = ({ title, subtitle, actionLabel, loading, disabled, interactionLocked = false, onSubmit, darkMode, tone = 'sky', afterButton = null, children, sectionRef = null }) => {
    const theme = {
        sky: {
            panel: darkMode ? 'border-cyan-900/70 bg-cyan-950/20' : 'border-cyan-200 bg-cyan-50/60',
            title: darkMode ? 'text-cyan-200' : 'text-cyan-900',
            button: 'from-sky-600 via-cyan-600 to-emerald-600',
        },
        violet: {
            panel: darkMode ? 'border-violet-900/70 bg-violet-950/20' : 'border-violet-200 bg-violet-50/60',
            title: darkMode ? 'text-violet-200' : 'text-violet-900',
            button: 'from-violet-600 via-fuchsia-600 to-pink-600',
        },
        emerald: {
            panel: darkMode ? 'border-emerald-900/70 bg-emerald-950/20' : 'border-emerald-200 bg-emerald-50/60',
            title: darkMode ? 'text-emerald-200' : 'text-emerald-900',
            button: 'from-emerald-600 via-teal-600 to-cyan-600',
        },
        amber: {
            panel: darkMode ? 'border-amber-900/70 bg-amber-950/20' : 'border-amber-200 bg-amber-50/60',
            title: darkMode ? 'text-amber-200' : 'text-amber-900',
            button: 'from-amber-500 via-orange-500 to-rose-500',
        },
    }[tone];

    return (
        <form ref={sectionRef} className={`${cardShell(darkMode)} ${theme.panel} flex flex-col gap-6 p-6`} onSubmit={onSubmit}>
            <div>
                <h3 className={`text-xl font-bold ${theme.title}`}>{title}</h3>
                {subtitle && (
                    <p className={`mt-1 max-w-3xl text-sm ${darkMode ? 'text-gray-400' : 'text-slate-500'}`}>{subtitle}</p>
                )}
            </div>
            <fieldset disabled={interactionLocked} className="space-y-4 min-w-0">
                {children}
            </fieldset>
            <button
                type="submit"
                disabled={disabled || interactionLocked}
                className={`w-full rounded-xl ${getActionButtonClass(loading, `bg-gradient-to-r ${theme.button}`)} px-5 py-3 text-sm font-bold text-white shadow-lg transition-all duration-200 hover:translate-y-[-1px] disabled:cursor-not-allowed`}
            >
                {loading ? `${actionLabel}...` : actionLabel}
            </button>
            {afterButton}
        </form>
    );
};

const ClusterPayloadEditor = ({ value, onChange, darkMode, minHeight = 168, maxHeight = 260 }) => {
    const [scrollTop, setScrollTop] = useState(0);
    const lineCount = Math.max(1, String(value || '').split(/\r?\n/).length);
    const lineHeight = 28;
    const verticalPadding = 12;

    return (
        <div
            className={`${darkMode ? 'border-cyan-900/60 bg-gray-950/80' : 'border-cyan-200 bg-white'} overflow-hidden rounded-xl border`}
            style={{ maxHeight: `${maxHeight}px` }}
        >
            <div className="flex">
                <div className={`${darkMode ? 'border-r border-cyan-900/60 bg-cyan-950/40 text-cyan-300/80' : 'border-r border-cyan-200 bg-cyan-50 text-cyan-700/80'} w-14 shrink-0 overflow-hidden text-right font-mono text-xs`}>
                    <div
                        style={{
                            transform: `translateY(-${scrollTop}px)`,
                            paddingTop: `${verticalPadding}px`,
                            paddingBottom: `${verticalPadding}px`,
                        }}
                    >
                        {Array.from({ length: lineCount }, (_, index) => (
                            <div
                                key={index}
                                className={`${darkMode ? 'border-b border-cyan-900/30' : 'border-b border-cyan-100'} flex h-7 items-center justify-end px-3`}
                            >
                                {index + 1}
                            </div>
                        ))}
                    </div>
                </div>
                <textarea
                    className={`${darkMode ? 'text-green-300' : 'text-slate-800'} min-w-0 flex-1 resize-none overflow-x-auto overflow-y-auto bg-transparent px-3 py-3 font-mono text-xs leading-7 outline-none`}
                    style={{
                        minHeight: `${minHeight}px`,
                        maxHeight: `${maxHeight}px`,
                        whiteSpace: 'pre',
                        lineHeight: `${lineHeight}px`,
                        paddingTop: `${verticalPadding}px`,
                        paddingBottom: `${verticalPadding}px`,
                        backgroundImage: darkMode
                            ? `repeating-linear-gradient(to bottom, transparent 0, transparent ${lineHeight - 1}px, rgba(8, 145, 178, 0.18) ${lineHeight - 1}px, rgba(8, 145, 178, 0.18) ${lineHeight}px)`
                            : `repeating-linear-gradient(to bottom, transparent 0, transparent ${lineHeight - 1}px, rgba(186, 230, 253, 0.9) ${lineHeight - 1}px, rgba(186, 230, 253, 0.9) ${lineHeight}px)`,
                        backgroundPositionY: `${verticalPadding}px`,
                    }}
                    wrap="off"
                    spellCheck={false}
                    value={value}
                    onChange={onChange}
                    onScroll={event => setScrollTop(event.target.scrollTop)}
                />
            </div>
        </div>
    );
};

const RuleCard = ({ title, item, index, darkMode, accent = 'blue', editable = false, onRuleChange }) => {
    const accentBar = {
        blue: darkMode ? 'from-cyan-500/50 to-blue-500/10' : 'from-cyan-400/60 to-blue-100',
        red: darkMode ? 'from-red-500/50 to-red-500/10' : 'from-red-400/60 to-red-100',
        green: darkMode ? 'from-emerald-500/50 to-emerald-500/10' : 'from-emerald-400/60 to-emerald-100',
        amber: darkMode ? 'from-amber-500/50 to-amber-500/10' : 'from-amber-400/60 to-amber-100',
        violet: darkMode ? 'from-violet-500/50 to-violet-500/10' : 'from-violet-400/60 to-violet-100',
    };

    return (
        <div className={`${cardShell(darkMode)} overflow-hidden`}>
            <div className={`h-1.5 bg-gradient-to-r ${accentBar[accent]}`} />
            <div className="p-4">
                <div className="mb-3 flex items-center justify-between gap-3">
                    <div>
                        <p className={`text-sm font-bold ${darkMode ? 'text-white' : 'text-slate-900'}`}>{title} #{index + 1}</p>
                        {item?.validation_error && (
                            <p className="mt-1 text-xs text-red-500">{item.validation_error}</p>
                        )}
                    </div>
                    {typeof item?.is_valid === 'boolean' && (
                        <span className={badgeShell(darkMode, item.is_valid ? 'green' : 'red')}>
                            {item.is_valid ? 'Valid' : 'Invalid'}
                        </span>
                    )}
                </div>
                <textarea
                    className={`${textareaShell(darkMode)} min-h-[132px] p-3 font-mono text-xs`}
                    value={item?.rule || ''}
                    onChange={editable && onRuleChange ? event => onRuleChange(event.target.value) : undefined}
                    readOnly={!editable}
                />
                {item?.instructions && (
                    <div className={`mt-3 rounded-xl px-3 py-2 text-sm ${darkMode ? 'bg-gray-800/80 text-gray-300' : 'bg-slate-100 text-slate-600'}`}>
                        {item.instructions}
                    </div>
                )}
                {Array.isArray(item?.validation_warnings) && item.validation_warnings.length > 0 && (
                    <div className="mt-3 flex flex-wrap gap-2">
                        {item.validation_warnings.map((warning, warningIndex) => (
                            <span key={`${warning}-${warningIndex}`} className={badgeShell(darkMode, 'amber')}>
                                {warning}
                            </span>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
};

const TabDefend = ({
    wafName,
    attackType,
    attackResults,
    setAttackResults,
    domain,
    darkMode,
    defendLoading = {},
    defendError = {},
    clusters = [],
    bypassedPayloads = [],
    ragSources = [],
    generatedRules = [],
    validRules = [],
    invalidRules = [],
    retriedRules = [],
    finalRules = [],
    detectedExistingRules = [],
    setClusters,
    setRagSources,
    setRagContext,
    setGeneratedRules,
    setValidRules,
    setInvalidRules,
    setRetriedRules,
    handleDefendClustering,
    handleDefendRag,
    handleDefendGenerateRules,
    handleDefendValidateRules,
    handleDefendRetryInvalidRules,
    handleDefendRefineRules,
    handleAutoDefend,
    setError,
    existingRules,
    setExistingRules,
    existingRuleFiles,
    setExistingRuleFiles,
}) => {
    const [loadingRetest, setLoadingRetest] = useState(false);
    const [showExistingRulesModal, setShowExistingRulesModal] = useState(false);
    const isAutoDefending = Boolean(defendLoading.auto);
    const clusteringReviewRef = useRef(null);
    const ragReviewRef = useRef(null);
    const generatedRulesReviewRef = useRef(null);
    const invalidRulesReviewRef = useRef(null);
    const validRulesReviewRef = useRef(null);
    const fixedRulesReviewRef = useRef(null);
    const clusteringStepRef = useRef(null);
    const ragStepRef = useRef(null);
    const generateStepRef = useRef(null);
    const validateStepRef = useRef(null);
    const retryStepRef = useRef(null);
    const refineStepRef = useRef(null);
    const lastAutoScrolledStepRef = useRef(null);

    const scrollToSection = ref => {
        ref?.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    };

    useEffect(() => {
        if (!isAutoDefending) {
            lastAutoScrolledStepRef.current = null;
            return;
        }

        const activeAutoStep = [
            ['clustering', defendLoading.clustering, clusteringStepRef],
            ['rag', defendLoading.rag, ragStepRef],
            ['generate', defendLoading.generate, generateStepRef],
            ['validate', defendLoading.validate, validateStepRef],
            ['retry', defendLoading.retry, retryStepRef],
            ['refine', defendLoading.refine, refineStepRef],
        ].find(([, isLoading]) => Boolean(isLoading));

        if (!activeAutoStep) {
            return;
        }

        const [stepName, , stepRef] = activeAutoStep;
        if (lastAutoScrolledStepRef.current === stepName) {
            return;
        }

        lastAutoScrolledStepRef.current = stepName;
        scrollToSection(stepRef);
    }, [
        isAutoDefending,
        defendLoading.clustering,
        defendLoading.rag,
        defendLoading.generate,
        defendLoading.validate,
        defendLoading.retry,
        defendLoading.refine,
    ]);

    const handleUploadRuleFiles = async event => {
        const selectedFiles = Array.from(event.target.files || []);
        if (selectedFiles.length === 0) return;

        setError && setError(null);

        try {
            const loadedFiles = await Promise.all(selectedFiles.map(file => new Promise((resolve, reject) => {
                const reader = new FileReader();
                reader.onload = loadEvent => {
                    resolve({
                        id: `${file.name}-${file.lastModified}-${file.size}`,
                        name: file.name,
                        content: typeof loadEvent.target?.result === 'string' ? loadEvent.target.result : '',
                    });
                };
                reader.onerror = () => reject(new Error(`Failed to read ${file.name}`));
                reader.readAsText(file);
            })));

            setExistingRuleFiles(prevFiles => [...prevFiles, ...loadedFiles]);
        } catch (err) {
            setError && setError(err.message || 'Failed to read uploaded rule files');
        } finally {
            event.target.value = '';
        }
    };

    const handleChangeUploadedFileContent = (fileId, nextContent) => {
        setExistingRuleFiles(prevFiles => prevFiles.map(file => (
            file.id === fileId ? { ...file, content: nextContent } : file
        )));
    };

    const handleDeleteUploadedFile = fileId => {
        setExistingRuleFiles(prevFiles => prevFiles.filter(file => file.id !== fileId));
    };

    const handleRetestAttack = async () => {
        if (!attackResults || attackResults.length === 0) return;
        setAttackResults(prev => prev.map(item => ({ ...item, bypassed: null, status_code: null, is_harmful: null })));
        setLoadingRetest(true);
        setError && setError(null);
        try {
            const res = await Services.apiTestAttack(domain, attackResults);
            const data = await res.json();
            if (!res.ok) {
                setError && setError(data?.error || `Server error: ${res.status}`);
                return;
            }

            setAttackResults(prev => prev.map(item => {
                const found = (data?.payloads || []).find(result => result.payload === item.payload);
                return found
                    ? { ...item, is_bypassed: found.is_bypassed, status_code: found.status_code, is_harmful: found.is_harmful }
                    : item;
            }));
        } catch (err) {
            setError && setError(err.message || 'Failed to connect to backend');
        } finally {
            setLoadingRetest(false);
        }
    };

    const handleClusterPayloadChange = (clusterId, nextValue) => {
        const nextPayloads = splitTextareaLines(nextValue);
        setClusters(prevClusters => prevClusters.map(cluster => (
            cluster.cluster_id === clusterId
                ? {
                    ...cluster,
                    payloads: nextPayloads,
                    representative_payload: nextPayloads[0] || '',
                    size: nextPayloads.length,
                }
                : cluster
        )));
    };

    const handleSourceContentChange = (sourceId, nextValue) => {
        setRagSources(prevSources => {
            const nextSources = prevSources.map(source => (
                source.id === sourceId ? { ...source, content: nextValue } : source
            ));
            setRagContext(nextSources.map(source => String(source.content || '').trim()).filter(Boolean).join('\n\n---\n\n'));
            return nextSources;
        });
    };

    const handleGeneratedRuleChange = (index, nextRule) => {
        setGeneratedRules(prevRules => prevRules.map((item, itemIndex) => (
            itemIndex === index ? { ...item, rule: nextRule } : item
        )));
    };

    const sectionError = step => defendError?.[step] ? (
        <div className="mt-4 rounded-xl border border-red-300 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-300">
            {defendError[step]}
        </div>
    ) : null;

    return (
        <div className="relative space-y-8" aria-busy={isAutoDefending}>
            {isAutoDefending && (
                <div
                    className="absolute inset-0 z-40 cursor-not-allowed bg-black/30"
                    style={{ pointerEvents: 'all' }}
                />
            )}
            <section className={`${cardShell(darkMode)} p-6`}>
                <div className="mb-4 flex flex-wrap items-center gap-3">
                    <span className={badgeShell(darkMode, 'slate')}>Domain: {domain || 'N/A'}</span>
                    <span className={badgeShell(darkMode, 'blue')}>WAF: {wafName || 'N/A'}</span>
                    <span className={badgeShell(darkMode, 'amber')}>Bypassed Payloads: {attackResults.filter(item => item.is_bypassed === true).length}</span>
                </div>
                <PayloadResultsTable
                    wafName={wafName}
                    payloads={attackResults.filter(item => item.is_bypassed === true && item.is_harmful === true)}
                    darkMode={darkMode}
                />
                <div className="mt-5 flex flex-wrap gap-3">
                    <button
                        type="button"
                        onClick={handleRetestAttack}
                        disabled={isAutoDefending || loadingRetest || !attackResults || attackResults.length === 0}
                        className={`rounded-xl ${getActionButtonClass(loadingRetest, 'bg-gradient-to-r from-emerald-600 to-teal-600')} px-5 py-2.5 text-sm font-bold text-white shadow-lg transition-all duration-200 hover:translate-y-[-1px] disabled:cursor-not-allowed`}
                    >
                        {loadingRetest ? 'Retesting...' : 'Retest Attack Results'}
                    </button>
                    <button
                        type="button"
                        onClick={handleAutoDefend}
                        disabled={defendLoading.auto || !attackResults || attackResults.length === 0}
                        className={`rounded-xl ${getActionButtonClass(defendLoading.auto, 'bg-gradient-to-r from-violet-600 via-fuchsia-600 to-pink-600')} px-5 py-2.5 text-sm font-bold text-white shadow-lg transition-all duration-200 hover:translate-y-[-1px] disabled:cursor-not-allowed`}
                    >
                        {defendLoading.auto ? 'Auto Defend...' : 'Auto Defend All Steps'}
                    </button>
                </div>
                {sectionError('auto')}
            </section>

            <StepSection
                sectionRef={clusteringStepRef}
                title="1. Clustering"
                subtitle="Cluster the above bypassed payloads. Using TF-IDF vectorization and HAC clustering."
                actionLabel="Run Clustering"
                loading={defendLoading.clustering}
                disabled={defendLoading.clustering || !attackResults || attackResults.length === 0}
                interactionLocked={isAutoDefending}
                onSubmit={event => {
                    event.preventDefault();
                    handleDefendClustering();
                }}
                darkMode={darkMode}
                tone="sky"
                afterButton={clusters.length > 0 ? (
                    <AfterStepNotice
                        darkMode={darkMode}
                        tone="cyan"
                        message={`Completed. ${clusters.length} clusters ready.`}
                        linkText="See Step 3."
                        onClick={() => scrollToSection(clusteringReviewRef)}
                    />
                ) : null}
            >
                {sectionError('clustering')}
                {clusters.length === 0 && (
                    <div className={`rounded-xl border border-dashed p-5 text-sm ${darkMode ? 'border-cyan-900 text-cyan-200/80' : 'border-cyan-300 text-cyan-800'}`}>
                        No clusters yet. Run this step to populate the Cluster Inputs block in step 3.
                    </div>
                )}
            </StepSection>

            <StepSection
                sectionRef={ragStepRef}
                title="2. RAG Retrieve"
                subtitle="Retrieve relevant sources using the current WAF name and the bypassed payloads."
                actionLabel="Run RAG Retrieve"
                loading={defendLoading.rag}
                disabled={defendLoading.rag || !attackResults || attackResults.length === 0}
                interactionLocked={isAutoDefending}
                onSubmit={event => {
                    event.preventDefault();
                    handleDefendRag();
                }}
                darkMode={darkMode}
                tone="violet"
                afterButton={ragSources.length > 0 ? (
                    <AfterStepNotice
                        darkMode={darkMode}
                        tone="violet"
                        message={`Completed. ${ragSources.length} sources ready.`}
                        linkText="See Step 3."
                        onClick={() => scrollToSection(ragReviewRef)}
                    />
                ) : null}
            >
                <div className="mb-4 grid gap-4 md:grid-cols-2">
                    <div>
                        <label className={`mb-2 block text-xs font-semibold uppercase tracking-wide ${darkMode ? 'text-gray-400' : 'text-slate-500'}`}>
                            WAF Name
                        </label>
                        <span className={infoValueShell(darkMode, 'blue')}>{wafName || 'N/A'}</span>
                    </div>
                    <div>
                        <label className={`mb-2 block text-xs font-semibold uppercase tracking-wide ${darkMode ? 'text-gray-400' : 'text-slate-500'}`}>
                            Attack Type
                        </label>
                        <span className={infoValueShell(darkMode, 'violet')}>{attackType || 'N/A'}</span>
                    </div>
                </div>
                <div className="mb-5">
                    <label className={`mb-2 block text-xs font-semibold uppercase tracking-wide ${darkMode ? 'text-gray-400' : 'text-slate-500'}`}>
                        Bypassed Payloads
                    </label>
                    <textarea
                        className={`${textareaShell(darkMode)} min-h-[120px] p-3 font-mono text-xs`}
                        value={bypassedPayloads.join('\n')}
                        readOnly
                    />
                </div>
                {sectionError('rag')}
                {ragSources.length === 0 && (
                    <div className={`rounded-xl border border-dashed p-5 text-sm ${darkMode ? 'border-violet-900 text-violet-200/80' : 'border-violet-300 text-violet-800'}`}>
                        No sources yet. Run this step to populate the Relevant Sources block in step 3.
                    </div>
                )}
            </StepSection>

            <StepSection
                sectionRef={generateStepRef}
                title="3. Generate Rules"
                subtitle="Generate WAF rules using the clustering and RAG retrieval results as input."
                actionLabel="Run Generate Rules"
                loading={defendLoading.generate}
                disabled={defendLoading.generate || clusters.length === 0 || ragSources.length === 0}
                interactionLocked={isAutoDefending}
                onSubmit={event => {
                    event.preventDefault();
                    handleDefendGenerateRules();
                }}
                darkMode={darkMode}
                tone="emerald"
                afterButton={generatedRules.length > 0 ? (
                    <AfterStepNotice
                        darkMode={darkMode}
                        tone="emerald"
                        message={`Completed. ${generatedRules.length} rules generated.`}
                        linkText="See Step 4."
                        onClick={() => scrollToSection(generatedRulesReviewRef)}
                    />
                ) : null}
            >
                <div className="mb-4 grid gap-4 lg:grid-cols-[260px_1fr]">
                    <div>
                        <label className={`mb-2 block text-xs font-semibold uppercase tracking-wide ${darkMode ? 'text-gray-400' : 'text-slate-500'}`}>
                            WAF Name
                        </label>
                        <span className={infoValueShell(darkMode, 'blue')}>{wafName || 'N/A'}</span>
                    </div>
                </div>
                {sectionError('generate')}
                <div className="mb-6 grid gap-6 xl:grid-cols-2">
                    <div ref={clusteringReviewRef} className={`${cardShell(darkMode)} ${darkMode ? 'border-cyan-900/60 bg-cyan-950/20' : 'border-cyan-200 bg-cyan-50/60'} p-4`}>
                        <div className="mb-4 flex items-center gap-3">
                            <h4 className={`text-lg font-bold ${darkMode ? 'text-cyan-200' : 'text-cyan-900'}`}>Clustering result</h4>
                            <span className={badgeShell(darkMode, 'blue')}>{clusters.length}</span>
                        </div>
                        {clusters.length === 0 ? (
                            <div className={`rounded-xl border border-dashed p-4 text-sm ${darkMode ? 'border-cyan-900 text-cyan-200/70' : 'border-cyan-300 text-cyan-800'}`}>
                                No clusters available for the generate step.
                            </div>
                        ) : (
                            <div className="max-h-[39rem] space-y-4 overflow-y-auto pr-2">
                                {clusters.map(cluster => (
                                    <div key={cluster.cluster_id} className={`${darkMode ? 'bg-gray-950/70 border-cyan-900/60' : 'bg-white border-cyan-200'} rounded-xl border p-4`}>
                                        <div className="mb-3 flex flex-wrap items-center gap-2">
                                            <span className={badgeShell(darkMode, 'blue')}>Cluster #{cluster.cluster_id}</span>
                                            <span className={badgeShell(darkMode, 'slate')}>Size: {cluster.size}</span>
                                            <span className={badgeShell(darkMode, 'amber')}>Attack: {cluster.attack_type || 'N/A'}</span>
                                        </div>
                                        <ClusterPayloadEditor
                                            darkMode={darkMode}
                                            minHeight={168}
                                            maxHeight={260}
                                            value={(cluster.payloads || []).join('\n')}
                                            onChange={event => handleClusterPayloadChange(cluster.cluster_id, event.target.value)}
                                        />
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>

                    <div ref={ragReviewRef} className={`${cardShell(darkMode)} ${darkMode ? 'border-violet-900/60 bg-violet-950/20' : 'border-violet-200 bg-violet-50/60'} p-4`}>
                        <div className="mb-4 flex items-center gap-3">
                            <h4 className={`text-lg font-bold ${darkMode ? 'text-violet-200' : 'text-violet-900'}`}>RAG Retrieve result</h4>
                            <span className={badgeShell(darkMode, 'violet')}>{ragSources.length}</span>
                        </div>
                        {ragSources.length === 0 ? (
                            <div className={`rounded-xl border border-dashed p-4 text-sm ${darkMode ? 'border-violet-900 text-violet-200/70' : 'border-violet-300 text-violet-800'}`}>
                                No sources available for the generate step.
                            </div>
                        ) : (
                            <div className="max-h-[39rem] space-y-4 overflow-y-auto pr-2">
                                {ragSources.map((source, index) => (
                                    <div key={source.id || `${source.source}-${index}`} className={`${darkMode ? 'bg-gray-950/70 border-violet-900/60' : 'bg-white border-violet-200'} rounded-xl border p-4`}>
                                        <div className="mb-3 flex flex-wrap gap-2">
                                            <span className={badgeShell(darkMode, 'slate')}>Type: {source.data_type || 'N/A'}</span>
                                            <span className={badgeShell(darkMode, 'slate')}>WAF: {source.waf_type || 'N/A'}</span>
                                            <span className={badgeShell(darkMode, 'violet')}>{source.source || `Source ${index + 1}`}</span>
                                        </div>
                                        <textarea
                                            className={`${textareaShell(darkMode)} min-h-[168px] p-3 font-mono text-xs`}
                                            value={source.content || ''}
                                            onChange={event => handleSourceContentChange(source.id, event.target.value)}
                                        />
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                </div>
                {generatedRules.length === 0 && (
                    <div className={`rounded-xl border border-dashed p-5 text-sm ${darkMode ? 'border-emerald-900 text-emerald-200/80' : 'border-emerald-300 text-emerald-800'}`}>
                        After this step runs, the generated rules will appear at the top of step 4 so you can edit them directly before syntax validation.
                    </div>
                )}
            </StepSection>

            <StepSection
                sectionRef={validateStepRef}
                title="4. Validate Syntax Rules"
                subtitle="Validate the syntax of the generated rules. The valid rules will go straight to Refine step while the invalid rules will be sent to Retry step."
                actionLabel="Run Validate"
                loading={defendLoading.validate}
                disabled={defendLoading.validate || generatedRules.length === 0}
                interactionLocked={isAutoDefending}
                onSubmit={event => {
                    event.preventDefault();
                    handleDefendValidateRules();
                }}
                darkMode={darkMode}
                afterButton={invalidRules.length > 0 || validRules.length > 0 ? (
                    <AfterStepNotice
                        darkMode={darkMode}
                        tone="amber"
                        message={`Completed. ${validRules.length} valid, ${invalidRules.length} invalid.`}
                        linkText={invalidRules.length > 0 ? 'See Step 5.' : 'See Step 6.'}
                        onClick={() => scrollToSection(invalidRules.length > 0 ? invalidRulesReviewRef : validRulesReviewRef)}
                    />
                ) : null}
            >
                {sectionError('validate')}
                <div ref={generatedRulesReviewRef} className="mb-6 space-y-4">
                    <div className="flex items-center gap-3">
                        <h4 className={`text-lg font-bold ${darkMode ? 'text-white' : 'text-slate-900'}`}>Generated Rules Input</h4>
                        <span className={badgeShell(darkMode, 'blue')}>{generatedRules.length}</span>
                    </div>
                    {generatedRules.length === 0 ? (
                        <div className={`rounded-xl border border-dashed p-5 text-sm ${darkMode ? 'border-gray-700 text-gray-400' : 'border-slate-300 text-slate-500'}`}>
                            No generated rules available for validation.
                        </div>
                    ) : (
                        <div className="max-h-[39rem] overflow-y-auto pr-2">
                            <div className="grid gap-4 xl:grid-cols-2">
                                {generatedRules.map((item, index) => (
                                    <RuleCard
                                        key={`generated-${index}`}
                                        title="Generated Rule"
                                        item={item}
                                        index={index}
                                        darkMode={darkMode}
                                        accent="blue"
                                        editable
                                        onRuleChange={nextRule => handleGeneratedRuleChange(index, nextRule)}
                                    />
                                ))}
                            </div>
                        </div>
                    )}
                </div>
                {invalidRules.length === 0 && validRules.length === 0 && (
                    <div className={`rounded-xl border border-dashed p-5 text-sm ${darkMode ? 'border-amber-900 text-amber-200/80' : 'border-amber-300 text-amber-800'}`}>
                        After this step runs, invalid rules will appear at the top of step 5 and valid rules will appear at the top of step 6.
                    </div>
                )}
            </StepSection>

            <StepSection
                sectionRef={retryStepRef}
                title="5. Retry Rules"
                subtitle="Retry fixing the invalid rules, fixed rules will be passed to Refine step."
                actionLabel="Run Retry"
                loading={defendLoading.retry}
                disabled={defendLoading.retry || invalidRules.length === 0}
                interactionLocked={isAutoDefending}
                onSubmit={event => {
                    event.preventDefault();
                    handleDefendRetryInvalidRules();
                }}
                darkMode={darkMode}
                afterButton={retriedRules.length > 0 ? (
                    <AfterStepNotice
                        darkMode={darkMode}
                        tone="amber"
                        message={`Completed. ${retriedRules.length} rules fixed.`}
                        linkText="See Step 6."
                        onClick={() => scrollToSection(fixedRulesReviewRef)}
                    />
                ) : null}
            >
                {sectionError('retry')}
                <div ref={invalidRulesReviewRef} className="mb-6 space-y-4">
                    <div className="flex items-center gap-3">
                        <h4 className={`text-lg font-bold ${darkMode ? 'text-white' : 'text-slate-900'}`}>Invalid Rules Input</h4>
                        <span className={badgeShell(darkMode, 'red')}>{invalidRules.length}</span>
                    </div>
                    {invalidRules.length === 0 ? (
                        <div className={`rounded-xl border border-dashed p-5 text-sm ${darkMode ? 'border-gray-700 text-gray-400' : 'border-slate-300 text-slate-500'}`}>
                            No invalid rules
                        </div>
                    ) : (
                        <div className="grid gap-4 xl:grid-cols-2">
                            {invalidRules.map((item, index) => (
                                <RuleCard
                                    key={`invalid-input-${index}`}
                                    title="Invalid Rule"
                                    item={item}
                                    index={index}
                                    darkMode={darkMode}
                                    accent="red"
                                />
                            ))}
                        </div>
                    )}
                </div>
                {retriedRules.length === 0 && (
                    <div className={`rounded-xl border border-dashed p-5 text-sm ${darkMode ? 'border-amber-900 text-amber-200/80' : 'border-amber-300 text-amber-800'}`}>
                        After this step runs, the fixed rules will appear at the top of step 6 so you can review them together with the valid rules before refinement.
                    </div>
                )}
            </StepSection>

            <StepSection
                sectionRef={refineStepRef}
                title="6. Refine Rules"
                subtitle="The final step uses the current WAF name, valid rules, fixed rules, and existing rules."
                actionLabel="Run Refine"
                loading={defendLoading.refine}
                disabled={defendLoading.refine || (validRules.length + retriedRules.length === 0)}
                interactionLocked={isAutoDefending}
                onSubmit={event => {
                    event.preventDefault();
                    handleDefendRefineRules();
                }}
                darkMode={darkMode}
                afterButton={finalRules.length > 0 && detectedExistingRules.length > 0 ? (
                    <ExistingRulesDetectedNotice
                        darkMode={darkMode}
                        count={detectedExistingRules.length}
                        onClick={() => setShowExistingRulesModal(true)}
                    />
                ) : null}
            >
                <div className="grid gap-4 lg:grid-cols-3">
                    <div>
                        <label className={`mb-2 block text-xs font-semibold uppercase tracking-wide ${darkMode ? 'text-gray-400' : 'text-slate-500'}`}>
                            WAF Name
                        </label>
                        <span className={infoValueShell(darkMode, 'blue')}>{wafName || 'N/A'}</span>
                    </div>
                    <div className={`${darkMode ? 'bg-gray-900/80' : 'bg-slate-50'} rounded-xl p-4`}>
                        <p className={`text-xs font-semibold uppercase tracking-wide ${darkMode ? 'text-gray-400' : 'text-slate-500'}`}>Valid Rules</p>
                        <p className={`mt-2 text-sm ${darkMode ? 'text-white' : 'text-slate-800'}`}>{validRules.length}</p>
                    </div>
                    <div className={`${darkMode ? 'bg-gray-900/80' : 'bg-slate-50'} rounded-xl p-4`}>
                        <p className={`text-xs font-semibold uppercase tracking-wide ${darkMode ? 'text-gray-400' : 'text-slate-500'}`}>Fixed Rules</p>
                        <p className={`mt-2 text-sm ${darkMode ? 'text-white' : 'text-slate-800'}`}>{retriedRules.length}</p>
                    </div>
                </div>
                <div className="mt-6 grid gap-6 xl:grid-cols-2">
                    <div ref={validRulesReviewRef} className="space-y-4">
                        <div className="flex items-center gap-3">
                            <h4 className={`text-lg font-bold ${darkMode ? 'text-white' : 'text-slate-900'}`}>Valid Rules Input</h4>
                            <span className={badgeShell(darkMode, 'green')}>{validRules.length}</span>
                        </div>
                        {validRules.length === 0 ? (
                            <div className={`rounded-xl border border-dashed p-5 text-sm ${darkMode ? 'border-gray-700 text-gray-400' : 'border-slate-300 text-slate-500'}`}>
                                No valid rules
                            </div>
                        ) : (
                            <div className="max-h-[39rem] space-y-4 overflow-y-auto pr-2">
                                {validRules.map((item, index) => (
                                    <RuleCard
                                        key={`valid-input-${index}`}
                                        title="Valid Rule"
                                        item={item}
                                        index={index}
                                        darkMode={darkMode}
                                        accent="green"
                                    />
                                ))}
                            </div>
                        )}
                    </div>
                    <div ref={fixedRulesReviewRef} className="space-y-4">
                        <div className="flex items-center gap-3">
                            <h4 className={`text-lg font-bold ${darkMode ? 'text-white' : 'text-slate-900'}`}>Fixed Rules Input</h4>
                            <span className={badgeShell(darkMode, 'amber')}>{retriedRules.length}</span>
                        </div>
                        {retriedRules.length === 0 ? (
                            <div className={`rounded-xl border border-dashed p-5 text-sm ${darkMode ? 'border-gray-700 text-gray-400' : 'border-slate-300 text-slate-500'}`}>
                                No fixed rules
                            </div>
                        ) : (
                            <div className="max-h-[39rem] space-y-4 overflow-y-auto pr-2">
                                {retriedRules.map((item, index) => (
                                    <RuleCard
                                        key={`fixed-input-${index}`}
                                        title="Fixed Rule"
                                        item={item}
                                        index={index}
                                        darkMode={darkMode}
                                        accent="amber"
                                    />
                                ))}
                            </div>
                        )}
                    </div>
                </div>
                <div className="mt-5 space-y-4">
                    <div>
                        <h4 className={`text-lg font-bold ${darkMode ? 'text-white' : 'text-slate-900'}`}>Existing Rules</h4>
                        <div className="flex flex-col gap-4 lg:flex-row mt-3">
                            <textarea
                                className={`${textareaShell(darkMode)} min-h-[120px] flex-1 p-3 font-mono text-xs`}
                                value={existingRules}
                                onChange={event => setExistingRules(event.target.value)}
                                placeholder="Paste existing rules here (plain text, JSON, or one rule per line)"
                            />
                            <label className={`inline-flex cursor-pointer items-center justify-center rounded-xl px-4 py-3 text-sm font-bold transition-all duration-200 ${darkMode ? 'bg-gray-800 text-gray-200 hover:bg-gray-700' : 'bg-slate-100 text-slate-700 hover:bg-slate-200'}`}>
                                Upload Files
                                <input
                                    type="file"
                                    accept={ACCEPTED_RULE_FILE_TYPES}
                                    multiple
                                    className="hidden"
                                    onChange={handleUploadRuleFiles}
                                />
                            </label>
                        </div>
                    </div>
                    {existingRuleFiles.length > 0 && (
                        <div className="grid gap-4">
                            {existingRuleFiles.map((file, index) => (
                                <div key={file.id} className={`${cardShell(darkMode)} p-4`}>
                                    <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
                                        <div className="flex flex-wrap items-center gap-2">
                                            <span className={badgeShell(darkMode, 'blue')}>Existing File #{index + 1}</span>
                                            <span className={badgeShell(darkMode, 'slate')}>{file.name}</span>
                                        </div>
                                        <button
                                            type="button"
                                            onClick={() => handleDeleteUploadedFile(file.id)}
                                            className="rounded-lg bg-red-600 px-3 py-1.5 text-xs font-bold text-white transition-all duration-200 hover:bg-red-700"
                                        >
                                            Delete
                                        </button>
                                    </div>
                                    <textarea
                                        className={`${textareaShell(darkMode)} min-h-[140px] p-3 font-mono text-xs`}
                                        value={file.content}
                                        onChange={event => handleChangeUploadedFileContent(file.id, event.target.value)}
                                    />
                                </div>
                            ))}
                        </div>
                    )}
                </div>
                {sectionError('refine')}
            </StepSection>

            <section className={`${cardShell(darkMode)} overflow-hidden`}>
                <div className={`bg-gradient-to-r px-6 py-5 ${darkMode ? 'from-emerald-900 via-teal-900 to-cyan-900' : 'from-emerald-100 via-teal-50 to-cyan-100'}`}>
                    <div className="flex flex-wrap items-center gap-3">
                        <h3 className={`text-2xl font-black tracking-tight ${darkMode ? 'text-white' : 'text-slate-900'}`}>
                            Final Rules
                        </h3>
                        <span className={badgeShell(darkMode, 'green')}>{finalRules.length} rules</span>
                    </div>
                    <p className={`mt-2 text-sm ${darkMode ? 'text-emerald-100/80' : 'text-slate-600'}`}>
                        This is the final result after validation, retry, and refinement.
                    </p>
                </div>
                <div className="p-6">
                    {finalRules.length === 0 ? (
                        <div className={`rounded-xl border border-dashed p-6 text-sm ${darkMode ? 'border-gray-700 text-gray-400' : 'border-slate-300 text-slate-500'}`}>
                            No final rules yet. Complete the Refine Rules step to get the final result.
                        </div>
                    ) : (
                        <div className="grid gap-5 xl:grid-cols-2">
                            {finalRules.map((item, index) => (
                                <RuleCard
                                    key={`final-${index}`}
                                    title="Final Rule"
                                    item={item}
                                    index={index}
                                    darkMode={darkMode}
                                    accent="green"
                                />
                            ))}
                        </div>
                    )}
                </div>
            </section>

            {showExistingRulesModal && detectedExistingRules.length > 0 && (
                <div
                    className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 px-4"
                    onClick={() => setShowExistingRulesModal(false)}
                >
                    <div
                        className={`${cardShell(darkMode)} w-full max-w-4xl p-6`}
                        onClick={event => event.stopPropagation()}
                    >
                        <div className="mb-4 flex items-center justify-between gap-4">
                            <div>
                                <h3 className={`text-xl font-bold ${darkMode ? 'text-white' : 'text-slate-900'}`}>
                                    Existing Rules Detected
                                </h3>
                                <p className={`mt-1 text-sm ${darkMode ? 'text-gray-400' : 'text-slate-500'}`}>
                                    {detectedExistingRules.length} rules were returned by the refine response.
                                </p>
                            </div>
                            <button
                                type="button"
                                onClick={() => setShowExistingRulesModal(false)}
                                className={`rounded-lg px-3 py-2 text-sm font-bold ${darkMode ? 'bg-gray-800 text-white hover:bg-gray-700' : 'bg-slate-100 text-slate-700 hover:bg-slate-200'}`}
                            >
                                Close
                            </button>
                        </div>
                        <div className="max-h-[32rem] space-y-3 overflow-y-auto pr-2">
                            {detectedExistingRules.map((rule, index) => (
                                <div key={`${rule}-${index}`} className="space-y-1">
                                    <label className={`block text-xs font-semibold uppercase tracking-wide ${darkMode ? 'text-gray-400' : 'text-slate-500'}`}>
                                        Rule #{index + 1}
                                    </label>
                                    <textarea
                                        readOnly
                                        value={rule}
                                        className={`${textareaShell(darkMode)} min-h-[96px] resize-y px-3 py-2 font-mono text-sm`}
                                    />
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default TabDefend;